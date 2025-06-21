package models

import "time"

type TokenEntry struct {
	BuildID  string    `json:"buildId,omitempty"`
	Token    string    `json:"token"`
	CSRF     string    `json:"csrf"`
	Created  time.Time `json:"created"`
	Expiry   int64     `json:"expiry"`
	IsActive bool      `json:"isActive"`
}

type TokenStore struct {
	Tokens []TokenEntry `json:"tokens"`
}
