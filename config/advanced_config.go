package config

import "time"

type AdvancedConfig struct {
	CleanupInterval      int  `json:"cleanupInterval"`
	InactivityThreshold  int  `json:"inactivityThreshold"`
	EnableProfiling      bool `json:"enableProfiling"`
	MaxHeaderBytes       int  `json:"maxHeaderBytes"`
	MaxTaskExecutionTime int  `json:"maxTaskExecutionTime"`
}

func NewDefaultAdvancedConfig() AdvancedConfig {
	return AdvancedConfig{
		CleanupInterval:      15,
		InactivityThreshold:  60,
		EnableProfiling:      false,
		MaxHeaderBytes:       1048576,
		MaxTaskExecutionTime: 120,
	}
}
func (c *AdvancedConfig) Validate() error {
	if c.CleanupInterval <= 0 {
		return ErrInvalidCleanupInterval
	}
	if c.InactivityThreshold <= 0 {
		return ErrInvalidInactivityThreshold
	}
	if c.MaxHeaderBytes <= 0 {
		return ErrInvalidMaxHeaderBytes
	}
	if c.MaxTaskExecutionTime <= 0 {
		return ErrInvalidMaxTaskExecutionTime
	}
	return nil
}
func (c *AdvancedConfig) GetCleanupInterval() time.Duration {
	return time.Duration(c.CleanupInterval) * time.Minute
}
func (c *AdvancedConfig) GetInactivityThreshold() time.Duration {
	return time.Duration(c.InactivityThreshold) * time.Minute
}
