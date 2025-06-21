package database

import (
	"bytes"
	"dr4ke-c2/server/config"
	"dr4ke-c2/server/models"
	"dr4ke-c2/server/utils"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var BucketNames = struct {
	Clients string
	Tasks   string
	History string
	Tokens  string
}{
	Clients: "clients",
	Tasks:   "tasks",
	History: "task_history",
	Tokens:  "tokens",
}

type BoltStore struct {
	db               *bolt.DB
	clientLimit      int
	cache            *clientCache
	writeQueue       chan writeOperation
	readaheadEnabled bool
	readaheadSize    int64
	metricsEnabled   bool
	wg               sync.WaitGroup
}
type writeOperation struct {
	operation func(*bolt.Tx) error
	result    chan error
}
type clientCache struct {
	clients      map[string]*models.Client
	cacheMutex   sync.RWMutex
	maxCacheSize int
}

func newClientCache(size int) *clientCache {
	return &clientCache{
		clients:      make(map[string]*models.Client),
		maxCacheSize: size,
	}
}
func (c *clientCache) get(id string) (*models.Client, bool) {
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()
	client, exists := c.clients[id]
	return client, exists
}
func (c *clientCache) set(client *models.Client) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()
	if len(c.clients) >= c.maxCacheSize && c.clients[client.ID] == nil {
		entriesToRemove := c.maxCacheSize / 10
		if entriesToRemove < 1 {
			entriesToRemove = 1
		}
		type cacheEntry struct {
			id       string
			lastSeen time.Time
		}
		entries := make([]cacheEntry, 0, len(c.clients))
		for id, cl := range c.clients {
			entries = append(entries, cacheEntry{id: id, lastSeen: cl.LastSeen})
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].lastSeen.Before(entries[j].lastSeen)
		})
		for i := 0; i < entriesToRemove && i < len(entries); i++ {
			delete(c.clients, entries[i].id)
		}
	}
	c.clients[client.ID] = client
}
func (c *clientCache) delete(id string) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()
	delete(c.clients, id)
}
func NewBoltStore(path string, clientLimit int) (*BoltStore, error) {
	options := &bolt.Options{
		Timeout:   3 * time.Second,
		NoSync:    false,
		MmapFlags: 0,
		ReadOnly:  false,
	}
	err := os.MkdirAll(filepath.Dir(path), 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}
	db, err := bolt.Open(path, 0600, options)
	if err != nil {
		return nil, fmt.Errorf("failed to open bolt database: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(BucketNames.Clients))
		if err != nil {
			return fmt.Errorf("create clients bucket: %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(BucketNames.Tasks))
		if err != nil {
			return fmt.Errorf("create tasks bucket: %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(BucketNames.History))
		if err != nil {
			return fmt.Errorf("create task history bucket: %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(BucketNames.Tokens))
		if err != nil {
			return fmt.Errorf("create tokens bucket: %w", err)
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create buckets: %w", err)
	}
	cacheSize := clientLimit / 4
	if cacheSize < 2500 {
		cacheSize = 2500
	}
	queueSize := 1000
	cfg := config.GetConfig()
	if cfg != nil && cfg.Batch.QueueSize > 0 {
		queueSize = cfg.Batch.QueueSize
	}
	readaheadSize := int64(4 * 1024 * 1024)
	resources, _ := utils.GetSystemResources()
	if resources != nil && resources.TotalRAM > 0 {
		ramBasedSize := int64(float64(resources.TotalRAM) * 0.001)
		if ramBasedSize > readaheadSize {
			readaheadSize = ramBasedSize
		}
		if readaheadSize > 64*1024*1024 {
			readaheadSize = 64 * 1024 * 1024
		}
	}
	store := &BoltStore{
		db:               db,
		clientLimit:      clientLimit,
		cache:            newClientCache(cacheSize),
		writeQueue:       make(chan writeOperation, queueSize),
		readaheadEnabled: true,
		readaheadSize:    readaheadSize,
		metricsEnabled:   true,
	}
	go store.processWriteQueue()
	return store, nil
}
func (s *BoltStore) processWriteQueue() {
	const maxBatchSize = 100
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[CRITICAL] Recovered from panic in writeQueue: %v\n", r)
			go s.processWriteQueue()
		}
	}()
	for {
		op, ok := <-s.writeQueue
		if !ok {
			return
		}
		ops := []writeOperation{op}
		batchSize := 1
	collectLoop:
		for batchSize < maxBatchSize {
			select {
			case nextOp, ok := <-s.writeQueue:
				if !ok {
					break collectLoop
				}
				ops = append(ops, nextOp)
				batchSize++
			default:
				break collectLoop
			}
		}
		var err error
		maxRetries := 3
		for attempt := 0; attempt < maxRetries; attempt++ {
			err = s.db.Update(func(tx *bolt.Tx) error {
				for i, operation := range ops {
					if err := operation.operation(tx); err != nil {
						select {
						case operation.result <- err:
						default:
						}
						s.wg.Done()
						ops[i] = ops[len(ops)-1]
						ops = ops[:len(ops)-1]
						continue
					}
					select {
					case operation.result <- nil:
					default:
					}
					s.wg.Done()
					if s.metricsEnabled {
						utils.IncrementDatabaseWrite()
					}
				}
				return nil
			})
			if err == nil || len(ops) == 0 {
				break
			}
			if err == bolt.ErrTimeout {
				fmt.Printf("[WARNING] BoltDB timeout, retrying (%d/%d)...\n", attempt+1, maxRetries)
				time.Sleep(100 * time.Millisecond * time.Duration(attempt+1))
				continue
			} else {
				break
			}
		}
		if err != nil && len(ops) > 0 {
			fmt.Printf("[ERROR] Database transaction failed after retries: %v\n", err)
			for _, operation := range ops {
				select {
				case operation.result <- err:
				default:
				}
				s.wg.Done()
			}
		}
	}
}
func (s *BoltStore) queueWrite(operation func(*bolt.Tx) error) error {
	resultChan := make(chan error, 1)
	s.wg.Add(1)
	s.writeQueue <- writeOperation{
		operation: operation,
		result:    resultChan,
	}
	return <-resultChan
}
func (s *BoltStore) AddClient(client *models.Client) error {
	if client == nil || client.ID == "" {
		return fmt.Errorf("invalid client: nil or empty ID")
	}
	if _, found := s.cache.get(client.ID); found {
		return ErrClientExists
	}
	err := s.queueWrite(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketNames.Clients))
		if b == nil {
			return fmt.Errorf("clients bucket not found")
		}
		if b.Get([]byte(client.ID)) != nil {
			return ErrClientExists
		}
		stats := b.Stats()
		if stats.KeyN >= s.clientLimit && s.clientLimit > 0 {
			return ErrDatabaseFull
		}
		buf, err := json.Marshal(client)
		if err != nil {
			return err
		}
		return b.Put([]byte(client.ID), buf)
	})
	if err == nil {
		s.cache.set(client)
	}
	return err
}
func (s *BoltStore) GetClient(id string) (*models.Client, error) {
	if client, found := s.cache.get(id); found {
		return client, nil
	}
	var client *models.Client
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketNames.Clients))
		data := b.Get([]byte(id))
		if data == nil {
			return ErrClientNotFound
		}
		client = &models.Client{}
		return json.Unmarshal(data, client)
	})
	if err != nil {
		return nil, err
	}
	s.cache.set(client)
	if s.metricsEnabled {
		utils.IncrementDatabaseRead()
	}
	return client, nil
}
func (s *BoltStore) UpdateClient(client *models.Client) error {
	if client == nil || client.ID == "" {
		return fmt.Errorf("invalid client: nil or empty ID")
	}
	s.cache.set(client)
	return s.queueWrite(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketNames.Clients))
		if b == nil {
			return fmt.Errorf("clients bucket not found")
		}
		if b.Get([]byte(client.ID)) == nil {
			return ErrClientNotFound
		}
		buf, err := json.Marshal(client)
		if err != nil {
			return err
		}
		return b.Put([]byte(client.ID), buf)
	})
}
func (s *BoltStore) DeleteClient(id string) error {
	s.cache.delete(id)
	return s.queueWrite(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketNames.Clients))
		if b.Get([]byte(id)) == nil {
			return ErrClientNotFound
		}
		return b.Delete([]byte(id))
	})
}
func (s *BoltStore) ListClients() ([]*models.Client, error) {
	var clients []*models.Client
	clientStats := make(map[string]int)
	var startTime time.Time
	if s.metricsEnabled {
		startTime = time.Now()
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketNames.Clients))
		return b.ForEach(func(k, v []byte) error {
			var client models.Client
			if err := json.Unmarshal(v, &client); err != nil {
				return err
			}
			clients = append(clients, &client)
			clientStats[client.Status]++
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if s.metricsEnabled {
		utils.IncrementDatabaseRead()
		utils.TrackRequestTime(time.Since(startTime))
		active := clientStats["Active"]
		idle := clientStats["Idle"]
		dead := clientStats["Dead"]
		writeQueueLen := len(s.writeQueue)
		utils.UpdateClientCounts(len(clients), active, idle, dead, writeQueueLen)
	}
	return clients, nil
}
func (s *BoltStore) GetWriteQueueLength() int {
	return len(s.writeQueue)
}
func (s *BoltStore) EnableMetrics(enabled bool) {
	s.metricsEnabled = enabled
}
func (s *BoltStore) SetReadAheadSize(size int64) {
	s.readaheadSize = size
}
func (s *BoltStore) CompactDatabase() error {
	tempFile := s.db.Path() + ".compact"
	stats, err := s.GetDatabaseStats()
	if err != nil {
		return err
	}
	var allClients []*models.Client
	allClients, err = s.ListClients()
	if err != nil {
		return err
	}
	if err := s.db.Close(); err != nil {
		return err
	}
	compactDB, err := bolt.Open(tempFile, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		s.db, _ = bolt.Open(s.db.Path(), 0600, &bolt.Options{Timeout: 5 * time.Second})
		return err
	}
	err = compactDB.Update(func(tx *bolt.Tx) error {
		for _, bucketName := range []string{BucketNames.Clients, BucketNames.Tasks, BucketNames.History} {
			_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		compactDB.Close()
		s.db, _ = bolt.Open(s.db.Path(), 0600, &bolt.Options{Timeout: 5 * time.Second})
		return err
	}
	err = compactDB.Update(func(tx *bolt.Tx) error {
		clientsBucket := tx.Bucket([]byte(BucketNames.Clients))
		for _, client := range allClients {
			clientData, err := json.Marshal(client)
			if err != nil {
				return err
			}
			if err := clientsBucket.Put([]byte(client.ID), clientData); err != nil {
				return err
			}
		}
		return nil
	})
	compactDB.Close()
	if err != nil {
		s.db, _ = bolt.Open(s.db.Path(), 0600, &bolt.Options{Timeout: 5 * time.Second})
		return err
	}
	origPath := s.db.Path()
	if err := os.Rename(tempFile, origPath); err != nil {
		s.db, _ = bolt.Open(origPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
		return err
	}
	s.db, err = bolt.Open(origPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return err
	}
	newStats, err := s.GetDatabaseStats()
	if err != nil {
		return err
	}
	fmt.Printf("[INFO] Database compaction complete. Before: %d bytes, After: %d bytes, Saved: %d bytes (%.2f%%)\n",
		stats.FileSize, newStats.FileSize, stats.FileSize-newStats.FileSize,
		float64(stats.FileSize-newStats.FileSize)/float64(stats.FileSize)*100)
	return nil
}

type DatabaseStats struct {
	FileSize    int64
	PageCount   int64
	FreePages   int
	PageSize    int
	TxCount     int
	KeyCount    int
	BucketStats map[string]BucketStats
}
type BucketStats struct {
	KeyCount   int
	DepthCount int
}

func (s *BoltStore) GetDatabaseStats() (*DatabaseStats, error) {
	stats := &DatabaseStats{
		BucketStats: make(map[string]BucketStats),
	}
	fileInfo, err := os.Stat(s.db.Path())
	if err != nil {
		return nil, err
	}
	stats.FileSize = fileInfo.Size()
	err = s.db.View(func(tx *bolt.Tx) error {
		dbStats := tx.DB().Stats()
		stats.PageCount = dbStats.TxStats.PageCount
		stats.PageSize = tx.DB().Info().PageSize
		for _, bucketName := range []string{BucketNames.Clients, BucketNames.Tasks, BucketNames.History} {
			bucket := tx.Bucket([]byte(bucketName))
			if bucket == nil {
				continue
			}
			bStats := bucket.Stats()
			stats.BucketStats[bucketName] = BucketStats{
				KeyCount:   bStats.KeyN,
				DepthCount: bStats.Depth,
			}
			stats.KeyCount += bStats.KeyN
		}
		return nil
	})
	return stats, err
}
func (s *BoltStore) AddTask(clientID string, task models.Task) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		clientBucket := tx.Bucket([]byte(BucketNames.Clients))
		if clientBucket == nil {
			return fmt.Errorf("client bucket not found")
		}
		data := clientBucket.Get([]byte(clientID))
		if data == nil {
			return ErrClientNotFound
		}
		var client models.Client
		if err := json.Unmarshal(data, &client); err != nil {
			return err
		}
		client.TaskQueue = append(client.TaskQueue, task)
		buf, err := json.Marshal(client)
		if err != nil {
			return err
		}
		if err := clientBucket.Put([]byte(clientID), buf); err != nil {
			return err
		}
		historyBucket := tx.Bucket([]byte(BucketNames.History))
		if historyBucket == nil {
			return fmt.Errorf("history bucket not found")
		}
		key := []byte(fmt.Sprintf("%s:%s", clientID, task.ID))
		taskHistory := struct {
			ClientID  string    `json:"clientId"`
			TaskID    string    `json:"taskId"`
			Command   string    `json:"command"`
			CreatedAt time.Time `json:"createdAt"`
			Updates   []struct {
				Status    string    `json:"status"`
				Result    string    `json:"result"`
				Timestamp time.Time `json:"timestamp"`
			} `json:"updates"`
		}{
			ClientID:  clientID,
			TaskID:    task.ID,
			Command:   task.Command,
			CreatedAt: task.CreatedAt,
			Updates: []struct {
				Status    string    `json:"status"`
				Result    string    `json:"result"`
				Timestamp time.Time `json:"timestamp"`
			}{
				{
					Status:    "pending",
					Result:    "",
					Timestamp: time.Now(),
				},
			},
		}
		historyData, err := json.Marshal(taskHistory)
		if err != nil {
			return err
		}
		return historyBucket.Put(key, historyData)
	})
}
func (s *BoltStore) GetTasks(clientID string) ([]models.Task, error) {
	var tasks []models.Task
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketNames.Clients))
		data := b.Get([]byte(clientID))
		if data == nil {
			return ErrClientNotFound
		}
		var client models.Client
		if err := json.Unmarshal(data, &client); err != nil {
			return err
		}
		tasks = client.TaskQueue
		client.TaskQueue = nil
		buf, err := json.Marshal(client)
		if err != nil {
			return err
		}
		return b.Put([]byte(clientID), buf)
	})
	if err != nil {
		return nil, err
	}
	return tasks, nil
}
func (s *BoltStore) ClearTasks(clientID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketNames.Clients))
		data := b.Get([]byte(clientID))
		if data == nil {
			return ErrClientNotFound
		}
		var client models.Client
		if err := json.Unmarshal(data, &client); err != nil {
			return err
		}
		client.TaskQueue = nil
		buf, err := json.Marshal(client)
		if err != nil {
			return err
		}
		return b.Put([]byte(clientID), buf)
	})
}
func (s *BoltStore) UpdateTaskStatus(clientID string, taskID string, status string, result string) error {
	if clientID == "" || taskID == "" {
		return fmt.Errorf("invalid task update: empty client ID or task ID")
	}
	return s.queueWrite(func(tx *bolt.Tx) error {
		historyBucket := tx.Bucket([]byte(BucketNames.History))
		if historyBucket == nil {
			return fmt.Errorf("history bucket not found")
		}
		key := []byte(fmt.Sprintf("%s:%s", clientID, taskID))
		var taskHistory struct {
			ClientID  string    `json:"clientId"`
			TaskID    string    `json:"taskId"`
			Command   string    `json:"command"`
			CreatedAt time.Time `json:"createdAt"`
			Updates   []struct {
				Status    string    `json:"status"`
				Result    string    `json:"result"`
				Timestamp time.Time `json:"timestamp"`
			} `json:"updates"`
		}
		data := historyBucket.Get(key)
		if data != nil {
			if err := json.Unmarshal(data, &taskHistory); err != nil {
				return err
			}
		} else {
			clientBucket := tx.Bucket([]byte(BucketNames.Clients))
			if clientBucket == nil {
				return fmt.Errorf("client bucket not found")
			}
			clientData := clientBucket.Get([]byte(clientID))
			if clientData == nil {
				return ErrClientNotFound
			}
			var client models.Client
			if err := json.Unmarshal(clientData, &client); err != nil {
				return err
			}
			taskHistory = struct {
				ClientID  string    `json:"clientId"`
				TaskID    string    `json:"taskId"`
				Command   string    `json:"command"`
				CreatedAt time.Time `json:"createdAt"`
				Updates   []struct {
					Status    string    `json:"status"`
					Result    string    `json:"result"`
					Timestamp time.Time `json:"timestamp"`
				} `json:"updates"`
			}{
				ClientID:  clientID,
				TaskID:    taskID,
				Command:   "unknown",
				CreatedAt: time.Now(),
				Updates: []struct {
					Status    string    `json:"status"`
					Result    string    `json:"result"`
					Timestamp time.Time `json:"timestamp"`
				}{},
			}
		}
		taskHistory.Updates = append(taskHistory.Updates, struct {
			Status    string    `json:"status"`
			Result    string    `json:"result"`
			Timestamp time.Time `json:"timestamp"`
		}{
			Status:    status,
			Result:    result,
			Timestamp: time.Now(),
		})
		updatedData, err := json.Marshal(taskHistory)
		if err != nil {
			return err
		}
		return historyBucket.Put(key, updatedData)
	})
}
func (s *BoltStore) CleanupInactiveClients(olderThan time.Duration) (int, error) {
	count := 0
	now := time.Now()
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketNames.Clients))
		return b.ForEach(func(k, v []byte) error {
			var client models.Client
			if err := json.Unmarshal(v, &client); err != nil {
				return err
			}
			if now.Sub(client.LastSeen) > olderThan {
				if err := b.Delete(k); err != nil {
					return err
				}
				count++
			}
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}
func (s *BoltStore) Close() error {
	close(s.writeQueue)
	s.wg.Wait()
	return s.db.Close()
}

type TaskHistoryEntry struct {
	ClientID  string       `json:"clientId"`
	TaskID    string       `json:"taskId"`
	Command   string       `json:"command"`
	CreatedAt time.Time    `json:"createdAt"`
	Updates   []TaskUpdate `json:"updates"`
}
type TaskUpdate struct {
	Status    string    `json:"status"`
	Result    string    `json:"result"`
	Timestamp time.Time `json:"timestamp"`
}

func (s *BoltStore) GetTaskHistory(clientID string, taskID string) (interface{}, error) {
	var taskHistory TaskHistoryEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		historyBucket := tx.Bucket([]byte(BucketNames.History))
		if historyBucket == nil {
			return fmt.Errorf("history bucket not found")
		}
		key := []byte(fmt.Sprintf("%s:%s", clientID, taskID))
		data := historyBucket.Get(key)
		if data == nil {
			return ErrTaskNotFound
		}
		return json.Unmarshal(data, &taskHistory)
	})
	if err != nil {
		return nil, err
	}
	return taskHistory, nil
}
func (s *BoltStore) GetClientTaskHistory(clientID string) ([]interface{}, error) {
	var history []interface{}
	err := s.db.View(func(tx *bolt.Tx) error {
		historyBucket := tx.Bucket([]byte(BucketNames.History))
		if historyBucket == nil {
			return fmt.Errorf("history bucket not found")
		}
		prefix := []byte(fmt.Sprintf("%s:", clientID))
		cursor := historyBucket.Cursor()
		for k, v := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cursor.Next() {
			var entry TaskHistoryEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				continue
			}
			history = append(history, entry)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return history, nil
}
func (s *BoltStore) SaveToken(clientID string, token string) error {
	return s.queueWrite(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketNames.Tokens))
		if b == nil {
			return fmt.Errorf("tokens bucket not found")
		}
		return b.Put([]byte(clientID), []byte(token))
	})
}
func (s *BoltStore) GetToken(clientID string) (string, error) {
	var token string
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketNames.Tokens))
		if b == nil {
			return fmt.Errorf("tokens bucket not found")
		}
		tokenBytes := b.Get([]byte(clientID))
		if tokenBytes == nil {
			return ErrTokenNotFound
		}
		token = string(tokenBytes)
		return nil
	})
	if err != nil {
		return "", err
	}
	return token, nil
}
func (s *BoltStore) DeleteToken(clientID string) error {
	return s.queueWrite(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketNames.Tokens))
		if b == nil {
			return fmt.Errorf("tokens bucket not found")
		}
		if b.Get([]byte(clientID)) == nil {
			return ErrTokenNotFound
		}
		return b.Delete([]byte(clientID))
	})
}
func (s *BoltStore) CleanupExpiredTokens() error {
	return s.queueWrite(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketNames.Tokens))
		if b == nil {
			return fmt.Errorf("tokens bucket not found")
		}
		now := time.Now().Unix()
		c := b.Cursor()
		for key, value := c.First(); key != nil; key, value = c.Next() {
			var unixTime int64
			_, err := fmt.Sscanf(string(value), "%d", &unixTime)
			if err != nil {
				fmt.Printf("[ERROR] Failed to parse token expiry for key %s: %v\n", string(key), err)
				continue
			}
			if unixTime < now {
				if err := b.Delete(key); err != nil {
					return fmt.Errorf("failed to delete expired token %s: %w", string(key), err)
				}
			}
		}
		return nil
	})
}
