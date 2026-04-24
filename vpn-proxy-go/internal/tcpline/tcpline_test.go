package tcpline

import (
	"testing"
)

func TestContainsNewline(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		expected bool
	}{
		{"no newline", []byte("hello"), false},
		{"has newline", []byte("hello\n"), true},
		{"has CRLF", []byte("hello\r\n"), true},
		{"empty", []byte(""), false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsNewline(tt.buf)
			if result != tt.expected {
				t.Errorf("containsNewline(%q) = %v, want %v", tt.buf, result, tt.expected)
			}
		})
	}
}

func TestFindNewline(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		expected int
	}{
		{"no newline", []byte("hello"), -1},
		{"newline at end", []byte("hello\n"), 5},
		{"newline in middle", []byte("hello\nworld"), 5},
		{"CRLF", []byte("hello\r\nworld"), 6},
		{"empty", []byte(""), -1},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findNewline(tt.buf)
			if result != tt.expected {
				t.Errorf("findNewline(%q) = %d, want %d", tt.buf, result, tt.expected)
			}
		})
	}
}
