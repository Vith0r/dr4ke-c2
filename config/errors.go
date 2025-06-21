package config

import "errors"

var (
	ErrInvalidPort                 = errors.New("invalid port configuration")
	ErrInvalidHost                 = errors.New("invalid host configuration")
	ErrInvalidClientLimit          = errors.New("invalid client limit")
	ErrInvalidReadTimeout          = errors.New("invalid read timeout")
	ErrInvalidWriteTimeout         = errors.New("invalid write timeout")
	ErrInvalidIdleTimeout          = errors.New("invalid idle timeout")
	ErrInvalidDatabaseType         = errors.New("invalid database type")
	ErrInvalidFilePath             = errors.New("invalid file path")
	ErrInvalidCacheSize            = errors.New("invalid cache size")
	ErrInvalidBoltTimeout          = errors.New("invalid bolt timeout")
	ErrInvalidFlushInterval        = errors.New("invalid flush interval")
	ErrInvalidMaxBatchSize         = errors.New("invalid max batch size")
	ErrInvalidQueueSize            = errors.New("invalid queue size")
	ErrInvalidCleanupInterval      = errors.New("invalid cleanup interval")
	ErrInvalidInactivityThreshold  = errors.New("invalid inactivity threshold")
	ErrInvalidMaxHeaderBytes       = errors.New("invalid max header bytes")
	ErrInvalidMaxTaskExecutionTime = errors.New("invalid max task execution time")
	ErrConfigFileNotFound          = errors.New("configuration file not found")
	ErrConfigFileRead              = errors.New("error reading configuration file")
	ErrConfigFileWrite             = errors.New("error writing configuration file")
	ErrConfigFileDecode            = errors.New("error decoding configuration file")
)
