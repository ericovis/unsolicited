package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ericovis/unsolicited/internal/classifier"
	"github.com/ericovis/unsolicited/internal/config"
	"github.com/ericovis/unsolicited/internal/database"
	"github.com/ericovis/unsolicited/internal/honeypot"
	"github.com/ericovis/unsolicited/internal/web"
	"github.com/ericovis/unsolicited/internal/worker"
)

func main() {
	cfg := config.Load()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Database
	pool, err := database.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer pool.Close()

	if err := database.RunMigrations(ctx, pool); err != nil {
		log.Fatalf("database migrations failed: %v", err)
	}

	// Classification worker
	cls := classifier.New(cfg.OllamaURL, cfg.OllamaModel)
	w := worker.New(pool, cls)
	go w.Start(ctx)

	// HTTP server
	router := web.NewRouter(pool)
	httpServer := &http.Server{
		Addr:         ":" + cfg.HTTPPort,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// SSH honeypot server
	sshServer := honeypot.NewSSHServer(pool, cfg.SSHPort)

	// Start servers
	go func() {
		log.Printf("HTTP server listening on :%s", cfg.HTTPPort)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	go func() {
		if err := sshServer.Start(); err != nil {
			log.Printf("SSH server error: %v", err)
		}
	}()

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("shutting down...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	httpServer.Shutdown(shutdownCtx)
	sshServer.Close()
	log.Println("shutdown complete")
}
