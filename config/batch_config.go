package config

import "time"

type BatchConfig struct {
	Enabled       bool `json:"enabled"`
	FlushInterval int  `json:"flushInterval"`
	MaxBatchSize  int  `json:"maxBatchSize"`
	QueueSize     int  `json:"queueSize"`
}

func NewDefaultBatchConfig() BatchConfig {
	return BatchConfig{
		Enabled:       true,
		FlushInterval: 500,
		MaxBatchSize:  200,
		QueueSize:     5000,
	}
}
func (c *BatchConfig) Validate() error {
	if c.FlushInterval <= 0 {
		return ErrInvalidFlushInterval
	}
	if c.MaxBatchSize <= 0 {
		return ErrInvalidMaxBatchSize
	}
	if c.QueueSize <= 0 {
		return ErrInvalidQueueSize
	}
	return nil
}
func (c *BatchConfig) GetFlushInterval() time.Duration {
	return time.Duration(c.FlushInterval) * time.Millisecond
}
