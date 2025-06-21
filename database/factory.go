package database

import (
	"dr4ke-c2/server/config"
	"fmt"
)

func NewClientStore(cfg *config.Configuration) (ClientStore, error) {
	switch cfg.Database.Type {
	case "memory":
		return NewInMemoryStore(), nil
	case "bolt":
		return NewBoltStore(cfg.Database.FilePath, cfg.Server.ClientLimit)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.Database.Type)
	}
}
