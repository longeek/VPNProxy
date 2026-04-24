package server

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// Test nextSessionID generates unique IDs
func TestNextSessionID(t *testing.T) {
	// Reset counter for test
	sessionCounter = 0
	id1 := nextSessionID()
	id2 := nextSessionID()
	if id1 == id2 {
		t.Error("Session IDs should be unique")
	}
	if len(id1) == 0 {
		t.Error("Session ID should not be empty")
	}
}

// Test loadAllowedTokens with token only
func TestLoadAllowedTokens_TokenOnly(t *testing.T) {
	tokens := LoadAllowedTokens("test-token", "")
	if len(tokens) != 1 {
		t.Errorf("Expected 1 token, got %d", len(tokens))
	}
	if !tokens["test-token"] {
		t.Error("Token 'test-token' should be in map")
	}
}

// Test loadAllowedTokens with file only
func TestLoadAllowedTokens_FileOnly(t *testing.T) {
	// Create temp file
	tmpFile := "test_tokens.txt"
	content := []byte("token1\ntoken2\n# comment\n\ntoken3\n")
	err := os.WriteFile(tmpFile, content, 0644)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile)

	tokens := LoadAllowedTokens("", tmpFile)
	if len(tokens) != 3 {
		t.Errorf("Expected 3 tokens, got %d", len(tokens))
	}
}

// Test resolveHost - requires DNS but we can test mock behavior
func TestResolveHost_Empty(t *testing.T) {
	// Test behavior when host is empty (edge case)
	// This requires valid DNS, so we test the error path
	// by calling resolveHost with an invalid host that will fail DNS
	// which requires network connection
	
	// Alternative: test that the function exists and can be called
	// We can't easily test DNS in unit tests without mocking
	_ = resolveHost
}

func TestLoadAllowedTokens_FileNotFound(t *testing.T) {
	// Test with non-existent file
	tokens := LoadAllowedTokens("", "non_existent_file.txt")
	if len(tokens) != 0 {
		t.Errorf("Expected 0 tokens for missing file, got %d", len(tokens))
	}
}

func TestLoadAllowedTokens_WithComments(t *testing.T) {
	tmpFile := "test_tokens_comments.txt"
	content := []byte("# comment\ntoken1\n# another comment\ntoken2\n\n#\n\ntoken3\n")
	err := os.WriteFile(tmpFile, content, 0644)
	defer os.Remove(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	
	tokens := LoadAllowedTokens("", tmpFile)
	if len(tokens) != 3 {
		t.Errorf("Expected 3 tokens, got %d", len(tokens))
	}
}

func TestParseAllowCIDRs_Invalid(t *testing.T) {
	// Test with invalid CIDR - should skip invalid and return nil
	nets := ParseAllowCIDRs("invalid-cidr-that-does-not-exist")
	// Function may return nil or empty slice for invalid
	// Just verify it doesn't panic
	_ = nets
}

func TestPeerAllowed_IPv6(t *testing.T) {
	// Test IPv6
	nets := ParseAllowCIDRs("10.0.0.0/8")
	ip := net.ParseIP("::1")
	result := peerAllowed(ip, nets)
	// IPv6 should not be in IPv4 network
	if result {
		t.Error("IPv6 should not match IPv4 network")
	}
}

// Test ParseAllowCIDRs empty
func TestParseAllowCIDRs_Empty(t *testing.T) {
	nets := ParseAllowCIDRs("")
	if len(nets) != 0 {
		t.Errorf("Expected 0 networks, got %d", len(nets))
	}
}

// Test ParseAllowCIDRs single
func TestParseAllowCIDRs_Single(t *testing.T) {
	nets := ParseAllowCIDRs("10.0.0.0/8")
	if len(nets) != 1 {
		t.Fatalf("Expected 1 network, got %d", len(nets))
	}
	if !nets[0].Contains(net.ParseIP("10.1.2.3")) {
		t.Error("Network should contain 10.1.2.3")
	}
}

// Test ParseAllowCIDRs multiple
func TestParseAllowCIDRs_Multiple(t *testing.T) {
	nets := ParseAllowCIDRs("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
	if len(nets) != 3 {
		t.Errorf("Expected 3 networks, got %d", len(nets))
	}
}

// Test peerAllowed empty networks
func TestPeerAllowed_EmptyNetworks(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	result := peerAllowed(ip, []*net.IPNet{})
	if !result {
		t.Error("peerAllowed should return true for empty networks")
	}
}

// Test peerAllowed in network
func TestPeerAllowed_InNetwork(t *testing.T) {
	nets := ParseAllowCIDRs("10.0.0.0/8")
	ip := net.ParseIP("10.0.0.1")
	result := peerAllowed(ip, nets)
	if !result {
		t.Error("peerAllowed should return true for IP in network")
	}
}

// Test peerAllowed not in network
func TestPeerAllowed_NotInNetwork(t *testing.T) {
	nets := ParseAllowCIDRs("10.0.0.0/8")
	ip := net.ParseIP("192.168.1.1")
	result := peerAllowed(ip, nets)
	if result {
		t.Error("peerAllowed should return false for IP not in network")
	}
}

// Test rateLimiter
func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(100, 20)
	// Exhaust all 20 tokens
	for i := 0; i < 20; i++ {
		if !rl.Allow() {
			t.Errorf("Request %d should be allowed", i)
		}
	}
	// Next should be denied (no tokens left)
	if rl.Allow() {
		t.Error("Should be rate limited now")
	}
	// Wait for refill (100 tokens/sec = 10ms per token)
	time.Sleep(50 * time.Millisecond)
	// Should have some tokens now (5 tokens refilled)
	if !rl.Allow() {
		t.Error("After refill, should be allowed")
	}
}

// Test AppError
func TestAppError(t *testing.T) {
	err := &AppError{
		Code:    "ERR_AUTH",
		Message: "Authentication failed",
	}
	msg := err.Error()
	if msg == "" {
		t.Error("Error message should not be empty")
	}
	
	// Test with wrapped error
	wrappedErr := &AppError{
		Code:    "ERR_CONNECT",
		Message: "Connection failed",
		Err:     fmt.Errorf("network error"),
	}
	wrappedMsg := wrappedErr.Error()
	if wrappedMsg == "" {
		t.Error("Wrapped error message should not be empty")
	}
}

// Test parseBootstrapLine
func TestParseBootstrapLine_Valid(t *testing.T) {
	line := `{"auth":"test-token","host":"example.com","port":443,"proto":"tcp"}`
	tokens := map[string]bool{"test-token": true}
	
	host, port, proto, err := parseBootstrapLine(line, tokens)
	if err != nil {
		t.Fatalf("parseBootstrapLine failed: %v", err)
	}
	if host != "example.com" {
		t.Errorf("Expected host example.com, got %s", host)
	}
	if port != 443 {
		t.Errorf("Expected port 443, got %d", port)
	}
	if proto != "tcp" {
		t.Errorf("Expected proto tcp, got %s", proto)
	}
}

func TestParseBootstrapLine_InvalidJSON(t *testing.T) {
	line := `invalid json`
	tokens := map[string]bool{"test-token": true}
	
	_, _, _, err := parseBootstrapLine(line, tokens)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestParseBootstrapLine_InvalidAuth(t *testing.T) {
	line := `{"auth":"wrong-token","host":"example.com","port":443}`
	tokens := map[string]bool{"test-token": true}
	
	_, _, _, err := parseBootstrapLine(line, tokens)
	if err == nil {
		t.Error("Expected error for invalid auth")
	}
}

func TestParseBootstrapLine_MissingHost(t *testing.T) {
	line := `{"auth":"test-token"}`
	tokens := map[string]bool{"test-token": true}
	
	_, _, _, err := parseBootstrapLine(line, tokens)
	if err == nil {
		t.Error("Expected error for missing host")
	}
}

func TestParseBootstrapLine_InvalidPort(t *testing.T) {
	line := `{"auth":"test-token","host":"example.com","port":99999}`
	tokens := map[string]bool{"test-token": true}
	
	_, _, _, err := parseBootstrapLine(line, tokens)
	if err == nil {
		t.Error("Expected error for invalid port")
	}
}

func TestParseBootstrapLine_InvalidProto(t *testing.T) {
	line := `{"auth":"test-token","host":"example.com","port":53,"proto":"invalid"}`
	tokens := map[string]bool{"test-token": true}
	
	_, _, _, err := parseBootstrapLine(line, tokens)
	if err == nil {
		t.Error("Expected error for invalid proto")
	}
}

func TestParseBootstrapLine_TCPPortZero(t *testing.T) {
	line := `{"auth":"test-token","host":"example.com","port":0,"proto":"tcp"}`
	tokens := map[string]bool{"test-token": true}
	
	_, _, _, err := parseBootstrapLine(line, tokens)
	if err == nil {
		t.Error("Expected error for tcp with port 0")
	}
}

func TestParseBootstrapLine_DefaultProto(t *testing.T) {
	// No proto specified, should default to tcp
	line := `{"auth":"test-token","host":"example.com","port":443}`
	tokens := map[string]bool{"test-token": true}
	
	_, _, proto, err := parseBootstrapLine(line, tokens)
	if err != nil {
		t.Fatalf("parseBootstrapLine failed: %v", err)
	}
	if proto != "tcp" {
		t.Errorf("Expected default proto tcp, got %s", proto)
	}
}

func TestParseBootstrapLine_UDP(t *testing.T) {
	line := `{"auth":"test-token","host":"example.com","port":53,"proto":"udp"}`
	tokens := map[string]bool{"test-token": true}
	
	_, port, proto, err := parseBootstrapLine(line, tokens)
	if err != nil {
		t.Fatalf("parseBootstrapLine failed: %v", err)
	}
	if proto != "udp" {
		t.Errorf("Expected proto udp, got %s", proto)
	}
	if port != 53 {
		t.Errorf("Expected port 53, got %d", port)
	}
}
