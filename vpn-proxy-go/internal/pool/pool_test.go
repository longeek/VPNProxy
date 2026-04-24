package pool

import (
	"testing"
	"time"
	
	"vpn-proxy-go/internal/tunnel"
)

func TestNew(t *testing.T) {
	cfg := &tunnel.Config{
		Server:     "example.com",
		ServerPort: 443,
		Token:      "test-token",
	}
	
	p := New(cfg, 5, 30*time.Second)
	if p == nil {
		t.Error("New should return non-nil Pool")
	}
	if p.maxSize != 5 {
		t.Errorf("Expected maxSize 5, got %d", p.maxSize)
	}
	if p.ttl != 30*time.Second {
		t.Errorf("Expected ttl 30s, got %v", p.ttl)
	}
}

func TestPool_Stop(t *testing.T) {
	cfg := &tunnel.Config{
		Server:     "example.com",
		ServerPort: 443,
		Token:      "test-token",
	}
	
	p := New(cfg, 5, 30*time.Second)
	// Stop should not panic even if not started
	p.Stop()
}

// Note: Testing Acquire and bootstrap requires network connection
// In production, these would use dependency injection or mocking

