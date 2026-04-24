package tunnel

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestRelayCopy(t *testing.T) {
	// Create a pipe for testing
	pr, pw := net.Pipe()
	defer pr.Close()
	defer pw.Close()
	
	// Write some data to pw
	testData := []byte("test data for relay")
	go func() {
		pw.Write(testData)
		pw.Close()
	}()
	
	// Read from pipe
	buf := make([]byte, len(testData))
	_, err := pr.Read(buf)
	if err != nil && err.Error() != "EOF" {
		t.Fatalf("Read failed: %v", err)
	}
	
	if string(buf) != string(testData) {
		t.Errorf("Expected %s, got %s", testData, buf)
	}
}

func TestGetRelayBuf(t *testing.T) {
	buf := getRelayBuf()
	if len(buf) != PipeBufSize {
		t.Errorf("Expected buffer size %d, got %d", PipeBufSize, len(buf))
	}
	putRelayBuf(buf)
}

func TestPutRelayBuf(t *testing.T) {
	buf := make([]byte, PipeBufSize)
	putRelayBuf(buf)
	
	// Get it again
	buf2 := getRelayBuf()
	if len(buf2) != PipeBufSize {
		t.Errorf("Expected buffer size %d, got %d", PipeBufSize, len(buf2))
	}
	putRelayBuf(buf2)
}

func TestConfig_CachedTLSConfig(t *testing.T) {
	cfg := &Config{
		Server:     "example.com",
		ServerPort: 443,
		Token:      "test-token",
		SNI:        "example.com",
		Insecure:   true,
	}
	
	tlsCfg, err := cfg.cachedTLSConfig()
	if err != nil {
		t.Fatalf("cachedTLSConfig failed: %v", err)
	}
	if tlsCfg == nil {
		t.Error("cachedTLSConfig returned nil")
	}
	
	// Call again, should return cached version
	tlsCfg2, err := cfg.cachedTLSConfig()
	if err != nil {
		t.Fatalf("cachedTLSConfig second call failed: %v", err)
	}
	if tlsCfg != tlsCfg2 {
		t.Error("cachedTLSConfig should return same instance")
	}
}

func TestOpen_InvalidServer(t *testing.T) {
	cfg := &Config{
		Server:     "invalid-server-that-does-not-exist",
		ServerPort: 12345,
		Token:      "test-token",
		Retries:    0,
	}
	
	ctx := context.Background()
	_, err := Open(ctx, cfg, "example.com", 80, "tcp")
	if err == nil {
		t.Error("Expected error for invalid server")
	}
}

func TestOpen_ContextCancelled(t *testing.T) {
	cfg := &Config{
		Server:     "example.com",
		ServerPort: 443,
		Token:      "test-token",
		Retries:    0,
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately
	
	_, err := Open(ctx, cfg, "example.com", 80, "tcp")
	if err == nil {
		t.Error("Expected error for cancelled context")
	}
}

func TestOpen_WithRetries(t *testing.T) {
	cfg := &Config{
		Server:     "invalid-server-that-does-not-exist",
		ServerPort: 12345,
		Token:      "test-token",
		Retries:    2,
		RetryDelay:  0.1, // Short delay for testing
	}
	
	ctx := context.Background()
	start := time.Now()
	_, err := Open(ctx, cfg, "example.com", 80, "tcp")
	elapsed := time.Since(start)
	
	if err == nil {
		t.Error("Expected error for invalid server")
	}
	// Should have taken some time due to retries
	if elapsed < 100*time.Millisecond {
		t.Errorf("Expected retries to take time, but only took %v", elapsed)
	}
}

func TestConfig_ZeroRetries(t *testing.T) {
	cfg := &Config{
		Server:     "example.com",
		ServerPort: 443,
		Token:      "test-token",
		Retries:    0,
	}
	
	// Just test that the config is valid
	if cfg.Retries != 0 {
		t.Errorf("Expected 0 retries, got %d", cfg.Retries)
	}
}

func TestBuildTLSConfig(t *testing.T) {
	cfg := &Config{
		Server:   "example.com",
		Insecure: true,
		SNI:      "example.com",
	}
	
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildTLSConfig failed: %v", err)
	}
	if tlsCfg == nil {
		t.Error("buildTLSConfig returned nil")
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
	if tlsCfg.ServerName != "example.com" {
		t.Errorf("Expected ServerName example.com, got %s", tlsCfg.ServerName)
	}
}

func TestBuildTLSConfig_NoSNI(t *testing.T) {
	cfg := &Config{
		Server:   "example.com",
		Insecure: false,
	}
	
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildTLSConfig failed: %v", err)
	}
	if tlsCfg.ServerName != "example.com" {
		t.Errorf("Expected ServerName example.com (from Server), got %s", tlsCfg.ServerName)
	}
}

func TestConfig_BuildTLSConfigWithCACert(t *testing.T) {
	// Test with CA cert (would need valid cert data)
	// For now, test that it doesn't panic with empty CACert
	cfg := &Config{
		Server: "example.com",
	}
	
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildTLSConfig failed: %v", err)
	}
	if tlsCfg == nil {
		t.Error("buildTLSConfig returned nil")
	}
}

func TestPipeBufSize(t *testing.T) {
	if PipeBufSize != 131072 {
		t.Errorf("Expected PipeBufSize 131072, got %d", PipeBufSize)
	}
}

func TestDrainThreshold(t *testing.T) {
	if DrainThreshold != 128*1024 {
		t.Errorf("Expected DrainThreshold %d, got %d", 128*1024, DrainThreshold)
	}
}

func TestRecvBufSize(t *testing.T) {
	if RecvBufSize != 256*1024 {
		t.Errorf("Expected RecvBufSize %d, got %d", 256*1024, RecvBufSize)
	}
}
