package models

import (
	"sync"
	"time"
)

const (
	StateActive       = "active"
	StateIdle         = "idle"
	StateInactive     = "inactive"
	StateRemoved      = "removed"
	IdleThreshold     = 1 * time.Hour
	InactiveThreshold = 24 * time.Hour
	RemovalThreshold  = 7 * 24 * time.Hour
	MaxTaskQueueSize  = 1000
	MaxTaskResultSize = 1024 * 1024
)

type Client struct {
	ID         string       `json:"id"`
	IPAddress  string       `json:"ipAddress"`
	FirstSeen  time.Time    `json:"firstSeen"`
	LastSeen   time.Time    `json:"lastSeen"`
	UserAgent  string       `json:"userAgent"`
	TaskQueue  []Task       `json:"taskQueue"`
	TasksMutex sync.RWMutex `json:"-"`
	Status     string       `json:"status"`
	State      string       `json:"state"`
	Info       ClientInfo   `json:"info"`
}
type ClientInfo struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Hostname     string `json:"hostname"`
	Username     string `json:"username"`
	ProcessName  string `json:"processName"`
}
type Task struct {
	ID          string    `json:"id"`
	Command     string    `json:"command"`
	CreatedAt   time.Time `json:"createdAt"`
	Status      string    `json:"status"`
	Result      string    `json:"result"`
	IsEncrypted bool      `json:"isEncrypted"`
}

func (c *Client) AddTask(task Task) {
	c.TasksMutex.Lock()
	defer c.TasksMutex.Unlock()
	if c.TaskQueue == nil {
		c.TaskQueue = make([]Task, 0)
	}
	if task.Status == "" {
		task.Status = "pending"
	}
	c.TaskQueue = append(c.TaskQueue, task)
}
func (c *Client) GetTasks() []Task {
	c.TasksMutex.Lock()
	defer c.TasksMutex.Unlock()
	if c.TaskQueue == nil {
		c.TaskQueue = make([]Task, 0)
	}
	tasks := c.TaskQueue
	c.TaskQueue = make([]Task, 0)
	return tasks
}
func (c *Client) HasTasks() bool {
	c.TasksMutex.RLock()
	defer c.TasksMutex.RUnlock()
	if c.TaskQueue == nil {
		c.TaskQueue = make([]Task, 0)
	}
	return len(c.TaskQueue) > 0
}
func (c *Client) UpdateLastSeen() {
	c.LastSeen = time.Now()
	c.UpdateStatus()
}
func (c *Client) UpdateStatus() {
	now := time.Now()
	timeSinceLastSeen := now.Sub(c.LastSeen)
	switch {
	case timeSinceLastSeen <= IdleThreshold:
		c.State = StateActive
		c.Status = "Online"
	case timeSinceLastSeen <= InactiveThreshold:
		c.State = StateIdle
		c.Status = "Idle"
	case timeSinceLastSeen <= RemovalThreshold:
		c.State = StateInactive
		c.Status = "Inactive"
	default:
		c.State = StateRemoved
		c.Status = "Removed"
	}
}
func (c *Client) IsActive() bool {
	return c.State == StateActive
}
func (c *Client) IsIdle() bool {
	return c.State == StateIdle
}
func (c *Client) IsInactive() bool {
	return c.State == StateInactive
}
func (c *Client) ShouldBeRemoved() bool {
	return c.State == StateRemoved
}
func (c *Client) GetLastSeenDuration() time.Duration {
	return time.Since(c.LastSeen)
}
func NewClient(id string, ipAddress string, userAgent string) *Client {
	now := time.Now()
	return &Client{
		ID:         id,
		IPAddress:  ipAddress,
		FirstSeen:  now,
		LastSeen:   now,
		UserAgent:  userAgent,
		TaskQueue:  make([]Task, 0),
		TasksMutex: sync.RWMutex{},
		Status:     "active",
		State:      StateActive,
		Info:       ClientInfo{},
	}
}
func NewTask(command string) Task {
	return Task{
		ID:        generateUUID(),
		Command:   command,
		CreatedAt: time.Now(),
		Status:    "pending",
	}
}
func generateUUID() string {
	return time.Now().Format("20060102-150405.000000000")
}
