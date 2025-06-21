package database

import (
	"dr4ke-c2/server/models"
	"time"
)

type ClientStore interface {
	AddClient(client *models.Client) error
	GetClient(id string) (*models.Client, error)
	UpdateClient(client *models.Client) error
	DeleteClient(id string) error
	ListClients() ([]*models.Client, error)
	CleanupInactiveClients(olderThan time.Duration) (int, error)
}
type TaskStore interface {
	AddTask(clientID string, task models.Task) error
	GetTasks(clientID string) ([]models.Task, error)
	ClearTasks(clientID string) error
	UpdateTaskStatus(clientID string, taskID string, status string, result string) error
	GetTaskHistory(clientID string, taskID string) (interface{}, error)
	GetClientTaskHistory(clientID string) ([]interface{}, error)
}
type TokenStore interface {
	SaveToken(clientID string, token string) error
	GetToken(clientID string) (string, error)
	DeleteToken(clientID string) error
}
type Store interface {
	ClientStore
	TaskStore
	TokenStore
	Close() error
}
