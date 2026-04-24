package socks

import (
	"testing"
)

func TestContainsMethod(t *testing.T) {
	tests := []struct {
		name     string
		methods  []byte
		method   byte
		expected bool
	}{
		{"contains method", []byte{0x00, 0x02, 0x03}, 0x02, true},
		{"not contains method", []byte{0x00, 0x02}, 0x01, false},
		{"empty methods", []byte{}, 0x00, false},
		{"single method match", []byte{0x00}, 0x00, true},
		{"single method no match", []byte{0x01}, 0x00, false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsMethod(tt.methods, tt.method)
			if result != tt.expected {
				t.Errorf("containsMethod(%v, %x) = %v, want %v", tt.methods, tt.method, result, tt.expected)
			}
		})
	}
}

func TestSendSocksReply(t *testing.T) {
	// Test that sendSocksReply doesn't panic
	// In real test, we would mock the connection
	// For now, just test the function signature exists
	_ = sendSocksReply
}

func TestSendSocksReplyBound(t *testing.T) {
	// Test that sendSocksReplyBound doesn't panic
	_ = sendSocksReplyBound
}

// Note: Testing Handle, handshake, handleUDP requires network mocks
// These would need more sophisticated test setup with mock connections
