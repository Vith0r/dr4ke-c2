package database

import (
	"dr4ke-c2/server/models"
	"sync"
	"time"
)

type InMemoryStore struct {
	clients     map[string]*models.Client
	taskHistory map[string]map[string]interface{}
	tokens      map[string]string
	mu          sync.RWMutex
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		clients:     make(map[string]*models.Client),
		taskHistory: make(map[string]map[string]interface{}),
		tokens:      make(map[string]string),
	}
}
func (s *InMemoryStore) AddClient(client *models.Client) error {
	if client == nil {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[client.ID]; exists {
		return ErrClientExists
	}
	s.clients[client.ID] = client
	return nil
}
func (s *InMemoryStore) GetClient(id string) (*models.Client, error) {
	if id == "" {
		return nil, ErrInvalidInput
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, exists := s.clients[id]
	if !exists {
		return nil, ErrClientNotFound
	}
	return client, nil
}
func (s *InMemoryStore) UpdateClient(client *models.Client) error {
	if client == nil {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[client.ID]; !exists {
		return ErrClientNotFound
	}
	s.clients[client.ID] = client
	return nil
}
func (s *InMemoryStore) DeleteClient(id string) error {
	if id == "" {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[id]; !exists {
		return ErrClientNotFound
	}
	delete(s.clients, id)
	delete(s.taskHistory, id)
	delete(s.tokens, id)
	return nil
}
func (s *InMemoryStore) ListClients() ([]*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	clients := make([]*models.Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	return clients, nil
}
func (s *InMemoryStore) AddTask(clientID string, task models.Task) error {
	if clientID == "" || task.ID == "" {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[clientID]; !exists {
		return ErrClientNotFound
	}
	history := s.getClientHistory(clientID)
	history[task.ID] = map[string]interface{}{
		"command":   task.Command,
		"createdAt": task.CreatedAt,
		"updates": []map[string]interface{}{
			{"status": "pending", "timestamp": time.Now()},
		},
	}
	return nil
}
func (s *InMemoryStore) GetTasks(clientID string) ([]models.Task, error) {
	if clientID == "" {
		return nil, ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[clientID]; !exists {
		return nil, ErrClientNotFound
	}
	history := s.getClientHistory(clientID)
	tasks := make([]models.Task, 0, len(history))
	for taskID, taskData := range history {
		taskMap := taskData.(map[string]interface{})
		task := models.Task{
			ID:        taskID,
			Command:   taskMap["command"].(string),
			CreatedAt: taskMap["createdAt"].(time.Time),
		}
		tasks = append(tasks, task)
	}
	return tasks, nil
}
func (s *InMemoryStore) ClearTasks(clientID string) error {
	if clientID == "" {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[clientID]; !exists {
		return ErrClientNotFound
	}
	delete(s.taskHistory, clientID)
	return nil
}
func (s *InMemoryStore) UpdateTaskStatus(clientID string, taskID string, status string, result string) error {
	if clientID == "" || taskID == "" {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[clientID]; !exists {
		return ErrClientNotFound
	}
	history := s.getClientHistory(clientID)
	taskHistory, exists := history[taskID].(map[string]interface{})
	if !exists {
		return ErrTaskNotFound
	}
	updates := taskHistory["updates"].([]map[string]interface{})
	updates = append(updates, map[string]interface{}{
		"status":    status,
		"result":    result,
		"timestamp": time.Now(),
	})
	taskHistory["updates"] = updates
	history[taskID] = taskHistory
	return nil
}
func (s *InMemoryStore) GetTaskHistory(clientID string, taskID string) (interface{}, error) {
	if clientID == "" || taskID == "" {
		return nil, ErrInvalidInput
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.clients[clientID]; !exists {
		return nil, ErrClientNotFound
	}
	history := s.getClientHistory(clientID)
	taskHistory, exists := history[taskID]
	if !exists {
		return nil, ErrTaskNotFound
	}
	return taskHistory, nil
}
func (s *InMemoryStore) GetClientTaskHistory(clientID string) ([]interface{}, error) {
	if clientID == "" {
		return nil, ErrInvalidInput
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.clients[clientID]; !exists {
		return nil, ErrClientNotFound
	}
	history := s.getClientHistory(clientID)
	result := make([]interface{}, 0, len(history))
	for _, taskHistory := range history {
		result = append(result, taskHistory)
	}
	return result, nil
}
func (s *InMemoryStore) CleanupInactiveClients(olderThan time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	count := 0
	for id, client := range s.clients {
		if now.Sub(client.LastSeen) > olderThan {
			delete(s.clients, id)
			delete(s.taskHistory, id)
			delete(s.tokens, id)
			count++
		}
	}
	return count, nil
}
func (s *InMemoryStore) SaveToken(clientID string, token string) error {
	if clientID == "" || token == "" {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[clientID]; !exists {
		return ErrClientNotFound
	}
	s.tokens[clientID] = token
	return nil
}
func (s *InMemoryStore) GetToken(clientID string) (string, error) {
	if clientID == "" {
		return "", ErrInvalidInput
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.clients[clientID]; !exists {
		return "", ErrClientNotFound
	}
	token, exists := s.tokens[clientID]
	if !exists {
		return "", ErrTokenNotFound
	}
	return token, nil
}
func (s *InMemoryStore) DeleteToken(clientID string) error {
	if clientID == "" {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[clientID]; !exists {
		return ErrClientNotFound
	}
	if _, exists := s.tokens[clientID]; !exists {
		return ErrTokenNotFound
	}
	delete(s.tokens, clientID)
	return nil
}
func (s *InMemoryStore) Close() error {
	return nil
}
func (s *InMemoryStore) getClientHistory(clientID string) map[string]interface{} {
	history, exists := s.taskHistory[clientID]
	if !exists {
		history = make(map[string]interface{})
		s.taskHistory[clientID] = history
	}
	return history
}
