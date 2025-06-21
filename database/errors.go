package database

import (
	"errors"
)

var (
	ErrClientNotFound     = errors.New("client not found")
	ErrClientExists       = errors.New("client already exists")
	ErrTaskNotFound       = errors.New("task not found")
	ErrDatabaseFull       = errors.New("database full, client limit reached")
	ErrInvalidInput       = errors.New("invalid input parameters")
	ErrTaskQueueFull      = errors.New("task queue is full")
	ErrTaskResultTooLarge = errors.New("task result exceeds maximum size")
	ErrResourceExhausted  = errors.New("resource limit exceeded")
	ErrInvalidState       = errors.New("invalid state")
	ErrTokenNotFound      = errors.New("token not found")
)
