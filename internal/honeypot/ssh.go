package honeypot

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"

	"crypto/x509"

	"github.com/gliderlabs/ssh"
	"github.com/jackc/pgx/v5/pgxpool"
	gossh "golang.org/x/crypto/ssh"
)

type SSHServer struct {
	db      *pgxpool.Pool
	server  *ssh.Server
	keyPath string
}

func NewSSHServer(db *pgxpool.Pool, port string) *SSHServer {
	s := &SSHServer{
		db:      db,
		keyPath: "/data/ssh_host_key",
	}

	s.server = &ssh.Server{
		Addr: ":" + port,
		PasswordHandler: func(ctx ssh.Context, password string) bool {
			s.logAttempt(ctx, password, "")
			return false // always reject
		},
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			fingerprint := gossh.FingerprintSHA256(key)
			s.logAttempt(ctx, "", fingerprint)
			return false // always reject
		},
		Handler: func(sess ssh.Session) {
			// Should never reach here since auth always fails, but just in case
			sess.Close()
		},
	}

	return s
}

func (s *SSHServer) logAttempt(ctx ssh.Context, password, publicKey string) {
	remoteAddr := ctx.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remoteAddr)

	_, err := s.db.Exec(context.Background(),
		`INSERT INTO ssh_attempts
			(ip, username, password, public_key, client_version, session_id)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		ip, ctx.User(), password, publicKey, ctx.ClientVersion(), ctx.SessionID(),
	)
	if err != nil {
		log.Printf("honeypot/ssh: insert error: %v", err)
	}
}

func (s *SSHServer) Start() error {
	if err := s.ensureHostKey(); err != nil {
		return fmt.Errorf("ssh host key: %w", err)
	}

	log.Printf("honeypot/ssh: listening on %s", s.server.Addr)
	return s.server.ListenAndServe()
}

func (s *SSHServer) Close() error {
	return s.server.Close()
}

func (s *SSHServer) ensureHostKey() error {
	// Try loading existing key
	if _, err := os.Stat(s.keyPath); err == nil {
		return ssh.HostKeyFile(s.keyPath)(s.server)
	}

	// Generate new ed25519 key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}

	// Ensure directory exists
	if dir := "/data"; dir != "" {
		os.MkdirAll(dir, 0700)
	}

	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}
	keyFile, err := os.OpenFile(s.keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, pemBlock); err != nil {
		return fmt.Errorf("encode pem: %w", err)
	}

	log.Printf("honeypot/ssh: generated new host key at %s", s.keyPath)
	return ssh.HostKeyFile(s.keyPath)(s.server)
}
