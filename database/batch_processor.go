package database

import (
	"dr4ke-c2/server/models"
	"dr4ke-c2/server/utils"
	"sync"
	"time"
)

type BatchProcessor struct {
	store         Store
	flushInterval time.Duration
	maxBatchSize  int
	taskUpdates   sync.Map
	clientUpdates sync.Map
	stopChan      chan struct{}
	resourceMgr   *utils.ResourceManager
}

func NewBatchProcessor(store Store, flushInterval time.Duration, maxBatchSize int, resourceMgr *utils.ResourceManager) *BatchProcessor {
	bp := &BatchProcessor{
		store:         store,
		flushInterval: flushInterval,
		maxBatchSize:  maxBatchSize,
		stopChan:      make(chan struct{}),
		resourceMgr:   resourceMgr,
	}
	go bp.processBatches()
	return bp
}
func (bp *BatchProcessor) AddTaskUpdate(clientID string, update interface{}) error {
	if bp.resourceMgr != nil {
		return bp.resourceMgr.WithThreadLimit(func() error {
			if clientID == "" {
				return nil
			}
			bp.taskUpdates.Store(clientID, update)
			return nil
		})
	} else {
		if clientID == "" {
			return nil
		}
		bp.taskUpdates.Store(clientID, update)
		return nil
	}
}
func (bp *BatchProcessor) UpdateClient(clientID string, update interface{}) error {
	if bp.resourceMgr != nil {
		return bp.resourceMgr.WithThreadLimit(func() error {
			if clientID == "" {
				return nil
			}
			bp.clientUpdates.Store(clientID, update)
			return nil
		})
	} else {
		if clientID == "" {
			return nil
		}
		bp.clientUpdates.Store(clientID, update)
		return nil
	}
}
func (bp *BatchProcessor) Flush() {
	if bp.resourceMgr != nil {
		bp.resourceMgr.WithThreadLimit(func() error {
			bp.flushUpdates()
			return nil
		})
	} else {
		bp.flushUpdates()
	}
}

func (bp *BatchProcessor) flushUpdates() {
	taskUpdates := make(map[string]interface{})
	clientUpdates := make(map[string]interface{})

	bp.taskUpdates.Range(func(key, value interface{}) bool {
		taskUpdates[key.(string)] = value
		return true
	})
	bp.clientUpdates.Range(func(key, value interface{}) bool {
		clientUpdates[key.(string)] = value
		return true
	})

	for _, update := range clientUpdates {
		if client, ok := update.(*models.Client); ok {
			if err := bp.store.UpdateClient(client); err != nil {
				continue
			}
		}
	}

	for clientID, update := range taskUpdates {
		if tasks, ok := update.([]models.Task); ok {
			for _, task := range tasks {
				if err := bp.store.AddTask(clientID, task); err != nil {
					continue
				}
			}
		}
	}

	bp.taskUpdates = sync.Map{}
	bp.clientUpdates = sync.Map{}
}
func (bp *BatchProcessor) processBatches() {
	ticker := time.NewTicker(bp.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			bp.Flush()
		case <-bp.stopChan:
			return
		}
	}
}
func (bp *BatchProcessor) Stop() {
	close(bp.stopChan)
}
