// Package config reads settings from the environment.
package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"zir/lcm/internal/crypto/envelope"
)

type Config struct {
	DatabaseURL    string // DATABASE_URL
	MasterKeyFile  string // MASTER_KEY_FILE
	PublicURL      string // PUBLIC_URL, e.g. https://fw.example.com
	Listen         string // LISTEN_ADDR, default :8080
	DataDir        string // DATA_DIR, default /data
	InsecureCookie bool   // COOKIE_INSECURE=1 for local http development only
}

func FromEnv() (Config, error) {
	c := Config{
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		MasterKeyFile:  os.Getenv("MASTER_KEY_FILE"),
		PublicURL:      strings.TrimRight(os.Getenv("PUBLIC_URL"), "/"),
		Listen:         getenv("LISTEN_ADDR", ":8080"),
		DataDir:        getenv("DATA_DIR", "/data"),
		InsecureCookie: os.Getenv("COOKIE_INSECURE") == "1",
	}
	if c.DatabaseURL == "" {
		return c, errors.New("DATABASE_URL is not set (локально: make user / make run, або eval \"$(make -s env)\" у каталозі lcm)")
	}
	if c.MasterKeyFile == "" {
		return c, errors.New("MASTER_KEY_FILE is not set (локально: make user / make run, або eval \"$(make -s env)\" у каталозі lcm)")
	}
	return c, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// LoadMasterKey reads the master key file: 64 hex chars or base64 of 32 bytes.
func LoadMasterKey(path string) (*envelope.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}
	s := strings.TrimSpace(string(data))
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		raw, err = base64.StdEncoding.DecodeString(s)
	}
	if err != nil || len(raw) != 32 {
		return nil, errors.New("master key: file must hold 32 bytes as hex or base64")
	}
	return envelope.New(raw)
}
