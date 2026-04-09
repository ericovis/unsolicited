package config

import "os"

type Config struct {
	DatabaseURL string
	OllamaURL   string
	OllamaModel string
	HTTPPort    string
	SSHPort     string
}

func Load() *Config {
	return &Config{
		DatabaseURL: getEnv("DATABASE_URL", "postgres://unsolicited:unsolicited@db:5432/unsolicited?sslmode=disable"),
		OllamaURL:   getEnv("OLLAMA_URL", "http://ollama:11434"),
		OllamaModel: getEnv("OLLAMA_MODEL", "gemma4"),
		HTTPPort:    getEnv("HTTP_PORT", "8080"),
		SSHPort:     getEnv("SSH_PORT", "2222"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
