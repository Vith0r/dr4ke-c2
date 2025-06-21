package controllers

import "time"

const (
	maxHeartbeatInterval = 2 * time.Minute
	maxCommandsPerMinute = 60
	suspiciousThreshold  = 10
	commandHistorySize   = 100
	heartbeatTimeout     = 5 * time.Minute
)

var maxCommandFrequency = map[string]int{
	"build":    15, 
	"download": 20, 
	"info":     40, 
}
