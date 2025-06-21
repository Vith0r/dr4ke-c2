package database

import (
	"dr4ke-c2/server/models"
	"sync"
	"time"
)

type BaseStore struct {
	clients     map[string]*models.Client
	taskHistory map[string]map[string]interface{}
	tokens      map[string]string
	mu          sync.RWMutex
}

func NewBaseStore() *BaseStore {
	return &BaseStore{
		clients:     make(map[string]*models.Client),
		taskHistory: make(map[string]map[string]interface{}),
		tokens:      make(map[string]string),
	}
}
func (s *BaseStore) validateClientID(clientID string) error {
	if clientID == "" {
		return ErrInvalidInput
	}
	return nil
}
func (s *BaseStore) validateTaskID(taskID string) error {
	if taskID == "" {
		return ErrInvalidInput
	}
	return nil
}
func (s *BaseStore) validateClient(client *models.Client) error {
	if client == nil {
		return ErrInvalidInput
	}
	if client.ID == "" {
		return ErrInvalidInput
	}
	return nil
}
func (s *BaseStore) validateTask(task models.Task) error {
	if task.ID == "" {
		return ErrInvalidInput
	}
	if task.Command == "" {
		return ErrInvalidInput
	}
	return nil
}
func (s *BaseStore) validateToken(token string) error {
	if token == "" {
		return ErrInvalidInput
	}
	return nil
}
func (s *BaseStore) getClientHistory(clientID string) map[string]interface{} {
	history, exists := s.taskHistory[clientID]
	if !exists {
		history = make(map[string]interface{})
		s.taskHistory[clientID] = history
	}
	return history
}
func (s *BaseStore) updateTaskHistory(clientID string, taskID string, status string, result string) error {
	history := s.getClientHistory(clientID)
	taskHistory, exists := history[taskID].(map[string]interface{})
	if !exists {
		return ErrTaskNotFound
	}
	updates, ok := taskHistory["updates"].([]map[string]interface{})
	if !ok {
		updates = []map[string]interface{}{}
	}
	updates = append(updates, map[string]interface{}{
		"status":    status,
		"result":    result,
		"timestamp": time.Now(),
	})
	taskHistory["updates"] = updates
	history[taskID] = taskHistory
	return nil
}
