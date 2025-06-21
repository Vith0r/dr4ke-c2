package controllers

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

type ClientBehavior struct {
	LastSeen         time.Time
	Heartbeats       int
	CommandsSent     int
	CommandHistory   []string
	IP               string
	UserAgent        string
	IsSuspicious     bool
	FirstSeen        time.Time
	TotalRequests    int
	LastHeartbeat    time.Time
	CommandFrequency map[string]int
}
type ClientBehaviorTracker struct {
	behaviors map[string]*ClientBehavior
	mu        sync.RWMutex
}

func NewClientBehaviorTracker() *ClientBehaviorTracker {
	tracker := &ClientBehaviorTracker{
		behaviors: make(map[string]*ClientBehavior),
	}
	go tracker.cleanupRoutine()
	return tracker
}
func (t *ClientBehaviorTracker) UpdateBehavior(r *http.Request) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	ip := getClientIP(r)
	behavior, exists := t.behaviors[ip]
	if !exists {
		behavior = &ClientBehavior{
			FirstSeen:        time.Now(),
			CommandFrequency: make(map[string]int),
		}
		t.behaviors[ip] = behavior
	}
	behavior.LastSeen = time.Now()
	behavior.TotalRequests++
	behavior.IP = ip
	behavior.UserAgent = r.UserAgent()
	command := getCommandFromPath(r.URL.Path)
	if command != "" {
		behavior.CommandsSent++
		behavior.CommandHistory = append(behavior.CommandHistory, command)
		if len(behavior.CommandHistory) > commandHistorySize {
			behavior.CommandHistory = behavior.CommandHistory[1:]
		}
		behavior.CommandFrequency[command]++
	}
	behavior.IsSuspicious = t.checkSuspiciousBehavior(behavior)
	return !behavior.IsSuspicious
}
func (t *ClientBehaviorTracker) GetCommandCount(r *http.Request) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	ip := getClientIP(r)
	if behavior, exists := t.behaviors[ip]; exists {
		return behavior.CommandsSent
	}
	return 0
}
func (t *ClientBehaviorTracker) RecordHeartbeat(r *http.Request) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ip := getClientIP(r)
	behavior, exists := t.behaviors[ip]
	if !exists {
		behavior = &ClientBehavior{
			FirstSeen:        time.Now(),
			CommandFrequency: make(map[string]int),
		}
		t.behaviors[ip] = behavior
	}
	behavior.LastHeartbeat = time.Now()
	behavior.Heartbeats++
}
func (t *ClientBehaviorTracker) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		t.cleanupOldBehaviors()
	}
}
func (t *ClientBehaviorTracker) cleanupOldBehaviors() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for ip, behavior := range t.behaviors {
		if now.Sub(behavior.LastSeen) > 24*time.Hour {
			delete(t.behaviors, ip)
		}
	}
}
func (t *ClientBehaviorTracker) checkSuspiciousBehavior(behavior *ClientBehavior) bool {
	for cmd, freq := range behavior.CommandFrequency {
		if maxFreq, ok := maxCommandFrequency[cmd]; ok && freq > maxFreq {
			return true
		}
	}
	if behavior.CommandsSent > maxCommandsPerMinute {
		return true
	}
	if len(behavior.CommandHistory) >= 2 {
		lastCmd := behavior.CommandHistory[len(behavior.CommandHistory)-1]
		prevCmd := behavior.CommandHistory[len(behavior.CommandHistory)-2]
		if lastCmd == prevCmd && time.Since(behavior.LastSeen) < time.Second {
			return true
		}
	}
	if behavior.LastHeartbeat.IsZero() || time.Since(behavior.LastHeartbeat) > heartbeatTimeout {
		return true
	}
	return false
}
func getCommandFromPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}
func getClientIP(r *http.Request) string {
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	return r.RemoteAddr
}
