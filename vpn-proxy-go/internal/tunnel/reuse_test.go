package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// ReusableTunnel chunk read/write tests
// ---------------------------------------------------------------------------

func TestReusableTunnel_ReadWriteChunks(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ct := NewReusableTunnel(client)
	st := NewReusableTunnel(server)

	// Write a chunk from client side
	payload := []byte("hello chunk")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := ct.WriteChunk(payload); err != nil {
			t.Errorf("WriteChunk: %v", err)
		}
	}()

	// Read on server side
	chunk, err := st.ReadChunk()
	if err != nil {
		t.Fatalf("ReadChunk: %v", err)
	}
	if chunk == nil {
		t.Fatal("ReadChunk returned nil (end-of-stream), expected data")
	}
	if !bytes.Equal(chunk, payload) {
		t.Errorf("chunk = %q, want %q", string(chunk), string(payload))
	}
	wg.Wait()
}

func TestReusableTunnel_MultipleChunks(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ct := NewReusableTunnel(client)
	st := NewReusableTunnel(server)

	payloads := [][]byte{
		[]byte("chunk one"),
		[]byte("chunk two"),
		[]byte("final"),
	}

	go func() {
		for _, p := range payloads {
			if err := ct.WriteChunk(p); err != nil {
				t.Errorf("WriteChunk: %v", err)
			}
		}
	}()

	for i, expected := range payloads {
		chunk, err := st.ReadChunk()
		if err != nil {
			t.Fatalf("ReadChunk #%d: %v", i, err)
		}
		if chunk == nil {
			t.Fatalf("ReadChunk #%d returned nil (eos), expected %q", i, string(expected))
		}
		if !bytes.Equal(chunk, expected) {
			t.Errorf("chunk #%d = %q, want %q", i, string(chunk), string(expected))
		}
	}
}

func TestReusableTunnel_EndOfStream(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ct := NewReusableTunnel(client)
	st := NewReusableTunnel(server)

	go func() {
		ct.WriteChunk([]byte("before"))
		ct.WriteEnd()
	}()

	// Read first chunk (data)
	chunk, err := st.ReadChunk()
	if err != nil {
		t.Fatalf("ReadChunk data: %v", err)
	}
	if chunk == nil {
		t.Fatal("expected data chunk, got nil (eos)")
	}

	// Read second - should be end-of-stream
	chunk, err = st.ReadChunk()
	if err != nil {
		t.Fatalf("ReadChunk eos: %v", err)
	}
	if chunk != nil {
		t.Errorf("expected nil (eos), got %q", string(chunk))
	}
}

func TestReusableTunnel_EOSAfterData(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ct := NewReusableTunnel(client)
	st := NewReusableTunnel(server)

	go func() {
		ct.WriteChunk([]byte("data1"))
		ct.WriteChunk([]byte("data2"))
		ct.WriteEnd()
		ct.WriteChunk([]byte("data3"))
	}()

	// Read data1
	c1, _ := st.ReadChunk()
	if c1 == nil || string(c1) != "data1" {
		t.Fatalf("expected data1, got %v", c1)
	}
	// Read data2
	c2, _ := st.ReadChunk()
	if c2 == nil || string(c2) != "data2" {
		t.Fatalf("expected data2, got %v", c2)
	}
	// Read EOS
	cEnd, _ := st.ReadChunk()
	if cEnd != nil {
		t.Fatalf("expected EOS (nil), got %q", string(cEnd))
	}
	// Read data3
	c3, _ := st.ReadChunk()
	if c3 == nil || string(c3) != "data3" {
		t.Fatalf("expected data3, got %v", c3)
	}
}

func TestReusableTunnel_LargeChunks(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ct := NewReusableTunnel(client)
	st := NewReusableTunnel(server)

	large := make([]byte, 100000)
	for i := range large {
		large[i] = byte(i % 256)
	}

	go func() {
		if err := ct.WriteChunk(large); err != nil {
			t.Errorf("WriteChunk large: %v", err)
		}
	}()

	chunk, err := st.ReadChunk()
	if err != nil {
		t.Fatalf("ReadChunk large: %v", err)
	}
	if chunk == nil {
		t.Fatal("expected data chunk, got nil")
	}
	if len(chunk) != len(large) {
		t.Fatalf("chunk length = %d, want %d", len(chunk), len(large))
	}
	for i, b := range chunk {
		if b != large[i] {
			t.Errorf("byte %d = %d, want %d", i, b, large[i])
			break
		}
	}
}

func TestReusableTunnel_Close(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	rt := NewReusableTunnel(client)
	rt.Close()

	// Read on server should get EOF
	_, err := server.Read([]byte{0})
	if err == nil {
		t.Error("expected error after close")
	}
}

func TestReusableTunnel_Conn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	rt := NewReusableTunnel(client)
	if rt.Conn() != client {
		t.Error("Conn() returned different connection")
	}
}

func TestReusableTunnel_WriteEndAfterClose(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ct := NewReusableTunnel(client)
	ct.Close()
	err := ct.WriteEnd()
	if err == nil {
		t.Error("expected error writing end after close")
	}
}

// ---------------------------------------------------------------------------
// RelayBidirectionalReuse tests
// ---------------------------------------------------------------------------

func TestRelayBidirectionalReuse_basic(t *testing.T) {
	clientPipe, serverPipe := newBufferedPipePair()
	defer clientPipe.Close()
	defer serverPipe.Close()

	ct := NewReusableTunnel(clientPipe)
	st := NewReusableTunnel(serverPipe)

	// Write data in both directions simultaneously
	var wg sync.WaitGroup
	wg.Add(2)

	// Server side: simulate relay server reading chunks and writing response
	go func() {
		defer wg.Done()
		// Read upload chunk
		chunk, err := st.ReadChunk()
		if err != nil {
			t.Errorf("server ReadChunk: %v", err)
			return
		}
		if string(chunk) != "request data" {
			t.Errorf("server got %q, want %q", string(chunk), "request data")
		}
		// Read end-of-stream
		if eos, _ := st.ReadChunk(); eos != nil {
			t.Error("expected EOS after request data")
		}
		// Write response
		if err := st.WriteChunk([]byte("response data")); err != nil {
			t.Errorf("server WriteChunk: %v", err)
		}
		st.WriteEnd()
	}()

	// Client side: relay client data
	go func() {
		defer wg.Done()
		client, srv := newBufferedPipePair()
		defer client.Close()
		defer srv.Close()

		go func() {
			srv.Write([]byte("request data"))
			srv.Close()
		}()

		var up, down uint64
		RelayBidirectionalReuse(client, ct, &up, &down)
	}()

	// Wait for relay to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for relay")
	}
}

func TestRelayBidirectionalReuse_stats(t *testing.T) {
	clientPipe, serverPipe := newBufferedPipePair()
	defer clientPipe.Close()
	defer serverPipe.Close()

	ct := NewReusableTunnel(clientPipe)
	st := NewReusableTunnel(serverPipe)

	var up, down uint64

	// Server
	go func() {
		chunk, _ := st.ReadChunk()
		for chunk != nil {
			chunk, _ = st.ReadChunk()
		}
		st.WriteChunk([]byte("response data"))
		st.WriteEnd()
		// Simulate next bootstrap
		st.ReadChunk()
	}()

	// Client
	client, srv := newBufferedPipePair()
	go func() {
		srv.Write([]byte("hello"))
		srv.Close()
	}()

	RelayBidirectionalReuse(client, ct, &up, &down)

	if atomic.LoadUint64(&up) == 0 {
		t.Error("expected non-zero upload stats")
	}
	if atomic.LoadUint64(&down) == 0 {
		t.Error("expected non-zero download stats")
	}
}

// ---------------------------------------------------------------------------
// RelayTCPServerReuse tests
// ---------------------------------------------------------------------------

func TestRelayTCPServerReuse_basic(t *testing.T) {
	clientPipe, serverPipe := newBufferedPipePair()
	defer clientPipe.Close()
	defer serverPipe.Close()

	ct := NewReusableTunnel(clientPipe)
	st := NewReusableTunnel(serverPipe)

	// Target (backend server)
	targetClient, targetServer := newBufferedPipePair()
	defer targetClient.Close()
	defer targetServer.Close()

	var wg sync.WaitGroup

	// Client sends upload
	wg.Add(1)
	go func() {
		defer wg.Done()
		ct.WriteChunk([]byte("upload data"))
		ct.WriteEnd()
		// Read response
		chunk, _ := ct.ReadChunk()
		if string(chunk) != "response data" {
			t.Errorf("client got %q, want %q", string(chunk), "response data")
		}
		chunk, _ = ct.ReadChunk()
		if chunk != nil {
			t.Error("expected EOS after response")
		}
	}()

	// Server relay
	wg.Add(1)
	go func() {
		defer wg.Done()
		stats := &SessionStats{}
		RelayTCPServerReuse(st, targetServer, stats)
	}()

	// Target server sends response
	go func() {
		buf := make([]byte, 1024)
		n, _ := targetClient.Read(buf)
		if string(buf[:n]) != "upload data" {
			t.Errorf("target got %q, want %q", string(buf[:n]), "upload data")
		}
		targetClient.Write([]byte("response data"))
		targetClient.Close()
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestRelayTCPServerReuse_stats(t *testing.T) {
	clientPipe, serverPipe := newBufferedPipePair()
	defer clientPipe.Close()
	defer serverPipe.Close()

	ct := NewReusableTunnel(clientPipe)
	st := NewReusableTunnel(serverPipe)
	targetClient, targetServer := newBufferedPipePair()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		ct.WriteChunk([]byte("upload"))
		ct.WriteEnd()
		ct.ReadChunk()
		ct.ReadChunk()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		stats := &SessionStats{}
		RelayTCPServerReuse(st, targetServer, stats)
		if stats.UploadBytes.Load() == 0 {
			t.Error("expected non-zero upload bytes")
		}
		if stats.DownloadBytes.Load() == 0 {
			t.Error("expected non-zero download bytes")
		}
	}()

	go func() {
		io.ReadAll(targetClient)
		targetClient.Write([]byte("response"))
		targetClient.Close()
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

// ---------------------------------------------------------------------------
// writeBootstrapChunk / readResponseChunk helper tests
// ---------------------------------------------------------------------------

func TestWriteBootstrapChunk(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ct := NewReusableTunnel(client)
	st := NewReusableTunnel(server)

	go func() {
		if err := WriteBootstrapChunk(ct, []byte(`{"auth":"t","host":"h","port":80}`)); err != nil {
			t.Errorf("WriteBootstrapChunk: %v", err)
		}
	}()

	data, err := ReadBootstrapChunk(st)
	if err != nil {
		t.Fatalf("ReadBootstrapChunk: %v", err)
	}
	if string(data) != `{"auth":"t","host":"h","port":80}` {
		t.Errorf("got %q, want bootstrap JSON", string(data))
	}
}

func TestWriteOKChunk(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ct := NewReusableTunnel(client)
	st := NewReusableTunnel(server)

	go func() {
		if err := WriteOKChunk(ct); err != nil {
			t.Errorf("WriteOKChunk: %v", err)
		}
	}()

	ok, err := ReadOKChunk(st)
	if err != nil {
		t.Fatalf("ReadOKChunk: %v", err)
	}
	if !ok {
		t.Error("expected OK=true, got false")
	}
}

func TestReadOKChunk_error(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	st := NewReusableTunnel(server)

	go func() {
		// Write an invalid response (not OK)
		data := append([]byte{TypeOK}, []byte("ERR bad")...)
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(data)))
		client.Write(length)
		client.Write(data)
	}()

	ok, err := ReadOKChunk(st)
	if err == nil {
		t.Error("expected error for non-OK response")
	}
	if ok {
		t.Error("expected ok=false for non-OK response")
	}
}

// ---------------------------------------------------------------------------
// End-to-end: bootstrap + relay + next bootstrap
// ---------------------------------------------------------------------------

func TestReuseBootstrapAndRelay(t *testing.T) {
	clientPipe, serverPipe := newBufferedPipePair()
	defer clientPipe.Close()
	defer serverPipe.Close()

	ct := NewReusableTunnel(clientPipe)
	st := NewReusableTunnel(serverPipe)

	targetClient, targetServer := newBufferedPipePair()
	defer targetClient.Close()
	defer targetServer.Close()

	var wg sync.WaitGroup

	// Phase 1: Bootstrap + Relay
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Send bootstrap chunk to server via ct
		if err := WriteBootstrapChunk(ct, []byte(`{"auth":"t","host":"example.com","port":80}`)); err != nil {
			t.Errorf("bootstrap: %v", err)
		}
		// Read OK response from server via ct
		ok, err := ReadOKChunk(ct)
		if err != nil || !ok {
			t.Errorf("expected OK, got ok=%v err=%v", ok, err)
		}

		// Send upload
		ct.WriteChunk([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		ct.WriteEnd()

		// Read response
		resp, _ := ct.ReadChunk()
		if string(resp) != "HTTP/1.1 200 OK\r\n\r\nbody" {
			t.Errorf("response = %q", string(resp))
		}
		ct.ReadChunk() // EOS
	}()

	// Simulate server
	go func() {
		// Read bootstrap from st
		bootstrap, _ := ReadBootstrapChunk(st)
		if bootstrap == nil {
			t.Error("expected bootstrap chunk")
			return
		}

		// Send OK via st
		WriteOKChunk(st)

		// Relay via st
		RelayTCPServerReuse(st, targetServer, &SessionStats{})
	}()

	// Simulate target response
	go func() {
		io.ReadAll(targetClient)
		targetClient.Write([]byte("HTTP/1.1 200 OK\r\n\r\nbody"))
		targetClient.Close()
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestReusableTunnel_EmptyWriteNoop(t *testing.T) {
	// WriteChunk with empty slice is a no-op; only WriteEnd sends EOS.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ct := NewReusableTunnel(client)
	st := NewReusableTunnel(server)

	go func() {
		ct.WriteChunk([]byte("data"))
		ct.WriteChunk([]byte{})   // no-op, should not block
		ct.WriteEnd()
	}()

	chunk, _ := st.ReadChunk()
	if chunk == nil || string(chunk) != "data" {
		t.Errorf("expected 'data', got %v", chunk)
	}
	// Should get EOS now
	eos, _ := st.ReadChunk()
	if eos != nil {
		t.Errorf("expected nil (eos), got %v", eos)
	}
}

func TestReusableTunnel_ConcurrentBidirectional(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ct := NewReusableTunnel(client)
	st := NewReusableTunnel(server)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			ct.WriteChunk([]byte("ping"))
		}
		ct.WriteEnd()
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			st.WriteChunk([]byte("pong"))
		}
		st.WriteEnd()
	}()

	// Client reads all pongs
	var clientPongs int
	for {
		chunk, err := ct.ReadChunk()
		if err != nil || chunk == nil {
			break
		}
		clientPongs++
	}
	// Server reads all pings
	var serverPings int
	for {
		chunk, err := st.ReadChunk()
		if err != nil || chunk == nil {
			break
		}
		serverPings++
	}

	if clientPongs != 10 {
		t.Errorf("client read %d pongs, want 10", clientPongs)
	}
	if serverPings != 10 {
		t.Errorf("server read %d pings, want 10", serverPings)
	}
	wg.Wait()
}
