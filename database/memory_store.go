package database

import (
	"dr4ke-c2/server/models"
	"dr4ke-c2/server/utils"
	"fmt"
	"runtime"
	"sync"
	"time"
)

type MemoryStore struct {
	clients       sync.Map
	tasks         sync.Map
	history       sync.Map
	limit         int
	cleanupTicker *time.Ticker
	stopChan      chan struct{}
	resourceMgr   *utils.ResourceManager
	config        *StoreConfig
	tokens        map[string]string
	mutex         sync.RWMutex
}
type StoreConfig struct {
	MaxTaskHistorySize int
	MaxTaskResultSize  int
	TaskHistoryTTL     time.Duration
	CleanupInterval    time.Duration
}

func NewMemoryStore(clientLimit int, resourceMgr *utils.ResourceManager) *MemoryStore {
	if resourceMgr == nil {
		panic("resource manager cannot be nil")
	}
	config := &StoreConfig{
		MaxTaskHistorySize: 1000,
		MaxTaskResultSize:  1024 * 1024,
		TaskHistoryTTL:     24 * time.Hour,
		CleanupInterval:    5 * time.Minute,
	}
	store := &MemoryStore{
		limit:         clientLimit,
		stopChan:      make(chan struct{}),
		cleanupTicker: time.NewTicker(config.CleanupInterval),
		resourceMgr:   resourceMgr,
		config:        config,
		tokens:        make(map[string]string),
	}
	go store.startCleanup()
	return store
}
func (s *MemoryStore) AddClient(client *models.Client) error {
	if client == nil {
		return ErrInvalidInput
	}
	return s.resourceMgr.WithThreadLimit(func() error {
		if s.limit > 0 {
			var count int
			s.clients.Range(func(_, _ interface{}) bool {
				count++
				return count <= s.limit
			})
			if count >= s.limit {
				return ErrDatabaseFull
			}
		}
		if _, loaded := s.clients.LoadOrStore(client.ID, client); loaded {
			return ErrClientExists
		}
		return nil
	})
}
func (s *MemoryStore) GetClient(id string) (*models.Client, error) {
	if id == "" {
		return nil, ErrInvalidInput
	}
	var result struct {
		client *models.Client
		err    error
	}
	s.resourceMgr.WithThreadLimit(func() error {
		if value, exists := s.clients.Load(id); exists {
			result.client = value.(*models.Client)
			return nil
		}
		result.err = ErrClientNotFound
		return result.err
	})
	return result.client, result.err
}
func (s *MemoryStore) UpdateClient(client *models.Client) error {
	if client == nil {
		return ErrInvalidInput
	}
	return s.resourceMgr.WithThreadLimit(func() error {
		if _, exists := s.clients.Load(client.ID); !exists {
			return ErrClientNotFound
		}
		s.clients.Store(client.ID, client)
		return nil
	})
}
func (s *MemoryStore) DeleteClient(id string) error {
	if id == "" {
		return ErrInvalidInput
	}
	return s.resourceMgr.WithThreadLimit(func() error {
		if _, exists := s.clients.Load(id); !exists {
			return ErrClientNotFound
		}
		s.clients.Delete(id)
		s.tasks.Delete(id)
		s.history.Delete(id)
		return nil
	})
}
func (s *MemoryStore) ListClients() ([]*models.Client, error) {
	var result struct {
		clients []*models.Client
		err     error
	}
	s.resourceMgr.WithThreadLimit(func() error {
		result.clients = make([]*models.Client, 0, 100)
		s.clients.Range(func(_, value interface{}) bool {
			result.clients = append(result.clients, value.(*models.Client))
			return true
		})
		return nil
	})
	return result.clients, result.err
}
func (s *MemoryStore) AddTask(clientID string, task models.Task) error {
	if clientID == "" || task.Command == "" {
		return ErrInvalidInput
	}
	return s.resourceMgr.WithThreadLimit(func() error {
		if _, exists := s.clients.Load(clientID); !exists {
			return ErrClientNotFound
		}
		if len(task.Result) > s.config.MaxTaskResultSize {
			return ErrTaskResultTooLarge
		}
		var tasks []models.Task
		if value, exists := s.tasks.LoadOrStore(clientID, make([]models.Task, 0, 10)); exists {
			tasks = value.([]models.Task)
		}
		tasks = append(tasks, task)
		s.tasks.Store(clientID, tasks)
		entry := TaskHistoryEntry{
			ClientID:  clientID,
			TaskID:    task.ID,
			Command:   task.Command,
			CreatedAt: task.CreatedAt,
			Updates: []TaskUpdate{
				{
					Status:    "pending",
					Result:    "",
					Timestamp: time.Now(),
				},
			},
		}
		var history map[string]TaskHistoryEntry
		if value, exists := s.history.LoadOrStore(clientID, make(map[string]TaskHistoryEntry)); exists {
			history = value.(map[string]TaskHistoryEntry)
		} else {
			history = make(map[string]TaskHistoryEntry)
		}
		if len(history) >= s.config.MaxTaskHistorySize {
			s.cleanupOldTaskHistory(clientID, history)
		}
		history[task.ID] = entry
		s.history.Store(clientID, history)
		return nil
	})
}
func (s *MemoryStore) cleanupOldTaskHistory(clientID string, history map[string]TaskHistoryEntry) {
	now := time.Now()
	for id, entry := range history {
		if now.Sub(entry.CreatedAt) > s.config.TaskHistoryTTL {
			delete(history, id)
		}
	}
}
func (s *MemoryStore) GetTasks(clientID string) ([]models.Task, error) {
	var tasks []models.Task
	var err error
	s.resourceMgr.WithThreadLimit(func() error {
		if clientID == "" {
			err = ErrInvalidInput
			return err
		}
		if _, exists := s.clients.Load(clientID); !exists {
			err = ErrClientNotFound
			return err
		}
		if value, exists := s.tasks.Load(clientID); exists {
			taskList := value.([]models.Task)
			tasks = make([]models.Task, len(taskList))
			copy(tasks, taskList)
			return nil
		}
		tasks = []models.Task{}
		return nil
	})
	return tasks, err
}
func (s *MemoryStore) ClearTasks(clientID string) error {
	return s.resourceMgr.WithThreadLimit(func() error {
		if clientID == "" {
			return ErrInvalidInput
		}
		if _, exists := s.clients.Load(clientID); !exists {
			return ErrClientNotFound
		}
		s.tasks.Store(clientID, make([]models.Task, 0))
		return nil
	})
}
func (s *MemoryStore) UpdateTaskStatus(clientID string, taskID string, status string, result string) error {
	return s.resourceMgr.WithThreadLimit(func() error {
		if clientID == "" || taskID == "" {
			return ErrInvalidInput
		}
		if _, exists := s.clients.Load(clientID); !exists {
			return ErrClientNotFound
		}
		var history map[string]TaskHistoryEntry
		if value, exists := s.history.LoadOrStore(clientID, make(map[string]TaskHistoryEntry)); exists {
			history = value.(map[string]TaskHistoryEntry)
		} else {
			history = make(map[string]TaskHistoryEntry)
		}
		entry, exists := history[taskID]
		if !exists {
			entry = TaskHistoryEntry{
				ClientID:  clientID,
				TaskID:    taskID,
				Command:   "unknown",
				CreatedAt: time.Now(),
				Updates:   make([]TaskUpdate, 0, 5),
			}
		}
		entry.Updates = append(entry.Updates, TaskUpdate{
			Status:    status,
			Result:    result,
			Timestamp: time.Now(),
		})
		history[taskID] = entry
		s.history.Store(clientID, history)
		return nil
	})
}
func (s *MemoryStore) CleanupInactiveClients(olderThan time.Duration) (int, error) {
	var count int
	var err error
	s.resourceMgr.WithThreadLimit(func() error {
		count = 0
		now := time.Now()
		s.clients.Range(func(key, value interface{}) bool {
			client := value.(*models.Client)
			if now.Sub(client.LastSeen) > olderThan {
				s.clients.Delete(key)
				s.tasks.Delete(key)
				s.history.Delete(key)
				count++
			}
			return true
		})
		if count > 0 {
			utils.LogOutput("[INFO] Cleaned up %d inactive clients", count)
		}
		return nil
	})
	return count, err
}
func (s *MemoryStore) startCleanup() {
	for {
		select {
		case <-s.cleanupTicker.C:
			s.CleanupInactiveClients(30 * time.Minute)
			s.resourceMgr.ForceGC()
		case <-s.stopChan:
			utils.LogOutput("[INFO] Stopping memory store cleanup routine")
			return
		}
	}
}
func (s *MemoryStore) Close() error {
	if s.cleanupTicker != nil {
		s.cleanupTicker.Stop()
	}
	close(s.stopChan)
	s.clients = sync.Map{}
	s.tasks = sync.Map{}
	s.history = sync.Map{}
	if s.resourceMgr != nil {
		s.resourceMgr.Close()
	}
	return nil
}
func (s *MemoryStore) GetTaskHistory(clientID string, taskID string) (interface{}, error) {
	var result interface{}
	var err error
	s.resourceMgr.WithThreadLimit(func() error {
		if clientID == "" || taskID == "" {
			err = ErrInvalidInput
			return err
		}
		if _, exists := s.clients.Load(clientID); !exists {
			err = ErrClientNotFound
			return err
		}
		if value, exists := s.history.Load(clientID); exists {
			history := value.(map[string]TaskHistoryEntry)
			if entry, exists := history[taskID]; exists {
				result = entry
				return nil
			}
		}
		err = ErrTaskNotFound
		return err
	})
	return result, err
}
func (s *MemoryStore) GetClientTaskHistory(clientID string) ([]interface{}, error) {
	var result []interface{}
	var err error
	s.resourceMgr.WithThreadLimit(func() error {
		if clientID == "" {
			err = ErrInvalidInput
			return err
		}
		if _, exists := s.clients.Load(clientID); !exists {
			err = ErrClientNotFound
			return err
		}
		if value, exists := s.history.Load(clientID); exists {
			history := value.(map[string]TaskHistoryEntry)
			result = make([]interface{}, 0, len(history))
			for _, entry := range history {
				result = append(result, entry)
			}
			return nil
		}
		result = []interface{}{}
		return nil
	})
	return result, err
}
func (s *MemoryStore) cleanupRoutine() {
	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		err := s.resourceMgr.WithThreadLimit(func() error {
			clientsToRemove := make([]string, 0)
			idleClients := 0
			inactiveClients := 0
			s.clients.Range(func(key, value interface{}) bool {
				client := value.(*models.Client)
				client.UpdateStatus()
				switch client.State {
				case models.StateIdle:
					idleClients++
				case models.StateInactive:
					inactiveClients++
				case models.StateRemoved:
					clientsToRemove = append(clientsToRemove, client.ID)
				}
				return true
			})
			if len(clientsToRemove) > 0 {
				for _, id := range clientsToRemove {
					s.clients.Delete(id)
					s.tasks.Delete(id)
					s.history.Delete(id)
				}
				utils.LogOutput("INFO", "MemoryStore", fmt.Sprintf("Removed %d inactive clients", len(clientsToRemove)))
			}
			if idleClients > 0 || inactiveClients > 0 {
				utils.LogOutput("INFO", "MemoryStore", fmt.Sprintf("Client states: %d idle, %d inactive", idleClients, inactiveClients))
			}
			if err := s.resourceMgr.CheckMemoryUsage(); err != nil {
				utils.LogOutput("INFO", "MemoryStore", "Memory pressure detected, forcing garbage collection")
				runtime.GC()
			}
			return nil
		})
		if err != nil {
			utils.LogOutput("WARN", "ResourceManager", "Failed to acquire thread for cleanup: "+err.Error())
		}
	}
}
func (s *MemoryStore) SaveToken(clientID string, token string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.tokens[clientID] = token
	return nil
}
func (s *MemoryStore) GetToken(clientID string) (string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	token, exists := s.tokens[clientID]
	if !exists {
		return "", ErrTokenNotFound
	}
	return token, nil
}
func (s *MemoryStore) DeleteToken(clientID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, exists := s.tokens[clientID]; !exists {
		return ErrTokenNotFound
	}
	delete(s.tokens, clientID)
	return nil
}
