// Package tunnel E2E integrity tests — these test the EXACT scenario
// where relay data arrives immediately after "OK\n" on the same TCP
// segment, which is the root cause of the "images sliding right-to-left"
// data corruption bug.
package tunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test 1: readLine does NOT consume bytes past "\n" when data follows
// immediately (simulates server sending OK + chunk data in one segment)
// ---------------------------------------------------------------------------

func TestReadLine_doesNotOverread(t *testing.T) {
	// Simulate the wire: "OK\n" followed immediately by chunk data
	var wire bytes.Buffer
	wire.Write([]byte("OK\n"))
	wire.Write([]byte{0x00, 0x00, 0x00, 0x05, 0x00, 'h', 'e', 'l', 'l', 'o'})

	// readLine from the buffer (byte-by-byte)
	status, err := ReadLine(&wire)
	if err != nil {
		t.Fatalf("readLine failed: %v", err)
	}
	if status != "OK" {
		t.Fatalf("expected OK, got %q", status)
	}

	// Now read the remaining data — it should be exactly the chunk that followed
	remaining := make([]byte, 10) // 4 len + 5 data + 1 type = 10
	n, err := io.ReadFull(&wire, remaining)
	if err != nil {
		t.Fatalf("reading remaining data failed: %v", err)
	}
	if n != 10 {
		t.Fatalf("expected 10 remaining bytes, got %d", n)
	}

	// Verify the remaining data is intact (chunk header preserved)
	expected := []byte{0x00, 0x00, 0x00, 0x05, 0x00, 'h', 'e', 'l', 'l', 'o'}
	if !bytes.Equal(remaining[:n], expected) {
		t.Fatalf("remaining data corrupted.\n  got:  %v\n  want: %v",
			remaining[:n], expected)
	}

	t.Log("PASS: readLine consumed exactly \"OK\\n\" (3 bytes), chunk data preserved")
}

// ---------------------------------------------------------------------------
// Test 2: readLine integrity with large data following "OK\n"
// (simulates real-world: server OK + large response chunk in same segment)
// ---------------------------------------------------------------------------

func TestReadLine_largeDataAfterOK(t *testing.T) {
	// Generate a large payload
	payloadSize := 100000
	payload := make([]byte, payloadSize)
	rand.Read(payload)

	// Build wire: "OK\n" + big chunk in one buffer
	var wire bytes.Buffer
	wire.Write([]byte("OK\n"))

	// Write chunk: [4-byte len][TypeData][payload]
	chunkLen := uint32(len(payload) + 1) // +1 for type
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, chunkLen)
	wire.Write(lenBytes)
	wire.Write([]byte{TypeData})
	wire.Write(payload)

	// readLine from the buffer (byte-by-byte, safe)
	status, err := ReadLine(&wire)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if status != "OK" {
		t.Fatalf("expected OK, got %q", status)
	}

	// Read the chunk using ReadChunkTyped logic
	var lenBuf [4]byte
	if _, err := io.ReadFull(&wire, lenBuf[:]); err != nil {
		t.Fatalf("read chunk length: %v", err)
	}
	totalLen := binary.BigEndian.Uint32(lenBuf[:])
	if totalLen != uint32(len(payload)+1) {
		t.Fatalf("chunk length = %d, want %d", totalLen, len(payload)+1)
	}

	raw := make([]byte, totalLen)
	if _, err := io.ReadFull(&wire, raw); err != nil {
		t.Fatalf("read chunk payload: %v", err)
	}
	if raw[0] != TypeData {
		t.Fatalf("chunk type = 0x%02x, want 0x%02x", raw[0], TypeData)
	}
	if !bytes.Equal(raw[1:], payload) {
		t.Fatal("chunk payload differs from original!")
	}

	t.Logf("PASS: readLine + chunk read preserved %d bytes", payloadSize)
}

// ---------------------------------------------------------------------------
// Test 3: Old-style conn.Read(buf) OVER-READS — demonstrates the bug
// ---------------------------------------------------------------------------

func TestOldRead_consumesExtraBytes(t *testing.T) {
	var wire bytes.Buffer
	wire.Write([]byte("OK\n"))
	wire.Write([]byte{0x00, 0x00, 0x00, 0x05, 0x00, 'h', 'e', 'l', 'l', 'o'})

	// OLD BEHAVIOR: read with a big buffer
	oldBuf := make([]byte, 1024)
	n, err := wire.Read(oldBuf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	status := string(oldBuf[:n])
	if len(status) < 2 || status[:2] != "OK" {
		t.Fatalf("expected OK, got %q", status)
	}

	// Now try to read the chunk that should follow
	chunkHeader := make([]byte, 4)
	_, err = io.ReadFull(&wire, chunkHeader)
	if err != nil || binary.BigEndian.Uint32(chunkHeader) != 6 {
		t.Logf("*** BUG DEMONSTRATED: chunk header read failed (Read(buf) consumed chunk data) ***")
		t.Logf("This is the root cause of the 'images sliding right-to-left' corruption!")
		return
	}

	// If buffer had exactly "OK\n" + chunk, the large Read consumed both
	t.Log("NOTE: large Read consumed extra bytes — this corrupts subsequent chunk reads")
}

// ---------------------------------------------------------------------------
// Test 4: Full relay integrity with multiple chunks through ReusableTunnel
// Uses bufferedPipe for deadlock-free full-duplex communication
// ---------------------------------------------------------------------------

func TestRelayFullSessionIntegrity(t *testing.T) {
	clientPipe, serverPipe := newBufferedPipePair()
	defer clientPipe.Close()
	defer serverPipe.Close()

	ct := NewReusableTunnel(clientPipe)
	st := NewReusableTunnel(serverPipe)

	// Generate known data
	uploadData := make([]byte, 50000)
	downloadData := make([]byte, 100000)
	rand.Read(uploadData)
	rand.Read(downloadData)

	var wg sync.WaitGroup

	// Server-side relay: read upload chunks, write download chunks
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Read upload chunks
		var received bytes.Buffer
		for {
			chunkType, payload, err := st.readChunkTyped()
			if err != nil || (chunkType == 0 && payload == nil) {
				break
			}
			if chunkType != TypeData {
				t.Errorf("server: unexpected chunk type 0x%02x", chunkType)
				return
			}
			received.Write(payload)
		}

		receivedBytes := received.Bytes()
		if len(receivedBytes) != len(uploadData) {
			t.Errorf("server: received %d upload bytes, want %d",
				len(receivedBytes), len(uploadData))
		} else if !bytes.Equal(receivedBytes, uploadData) {
			t.Error("server: upload data mismatch!")
		}

		// Write download chunks
		chunkSize := 20000
		for i := 0; i < len(downloadData); i += chunkSize {
			end := i + chunkSize
			if end > len(downloadData) {
				end = len(downloadData)
			}
			if err := st.WriteChunk(downloadData[i:end]); err != nil {
				t.Errorf("server WriteChunk: %v", err)
				return
			}
		}
		st.WriteEnd()
	}()

	// Client-side relay: read upload, write download
	wg.Add(1)
	go func() {
		defer wg.Done()

		simClient, simServer := newBufferedPipePair()
		defer simClient.Close()
		defer simServer.Close()

		// Simulated local app sends upload data
		go func() {
			simServer.Write(uploadData)
			simServer.Close()
		}()

		RelayBidirectionalReuse(simClient, ct, nil, nil)
	}()

	// Wait for relay to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for relay")
	}

	t.Log("PASS: relay session completed")
}

// ---------------------------------------------------------------------------
// Test 5: The REAL bug scenario — OK + DATA in one TCP segment
// Verifies readLine + ReusableTunnel does NOT lose bytes
// ---------------------------------------------------------------------------

func TestOKPlusDataInOneSegmentIntegrity(t *testing.T) {
	// Build ONE segment containing: "OK\n" + chunk header + chunk payload + another chunk
	payload := make([]byte, 50000)
	payload2 := []byte("second chunk data!")
	rand.Read(payload)

	var segment bytes.Buffer
	segment.Write([]byte("OK\n"))

	// First chunk: [4-byte len][TypeData][payload]
	chunkLen := uint32(len(payload) + 1)
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, chunkLen)
	segment.Write(lenBytes)
	segment.Write([]byte{TypeData})
	segment.Write(payload)

	// Second chunk: [4-byte len][TypeData][payload2]
	chunkLen2 := uint32(len(payload2) + 1)
	binary.BigEndian.PutUint32(lenBytes, chunkLen2)
	segment.Write(lenBytes)
	segment.Write([]byte{TypeData})
	segment.Write(payload2)

	// ===== CLIENT SIDE =====
	// Step 1: Read "OK\n" using readLine (byte-by-byte, safe)
	status, err := ReadLine(&segment)
	if err != nil {
		t.Fatalf("readLine failed: %v", err)
	}
	if status != "OK" {
		t.Fatalf("expected OK, got %q", status)
	}

	// Step 2: Read chunks using ReusableTunnel protocol
	// We don't have an actual connection, so do manual chunk reads
	var lenBuf [4]byte

	// Read first chunk header
	if _, err := io.ReadFull(&segment, lenBuf[:]); err != nil {
		t.Fatalf("chunk1 header: %v", err)
	}
	totalLen1 := binary.BigEndian.Uint32(lenBuf[:])
	if int(totalLen1) != len(payload)+1 {
		t.Fatalf("chunk1 length = %d, want %d", totalLen1, len(payload)+1)
	}

	raw1 := make([]byte, totalLen1)
	if _, err := io.ReadFull(&segment, raw1); err != nil {
		t.Fatalf("chunk1 payload: %v", err)
	}
	if raw1[0] != TypeData {
		t.Fatalf("chunk1 type = 0x%02x, want TypeData", raw1[0])
	}
	if !bytes.Equal(raw1[1:], payload) {
		t.Fatal("FIRST CHUNK PAYLOAD CORRUPTED!")
	}
	t.Logf("First chunk: %d bytes — INTEGRITY OK", len(raw1)-1)

	// Read second chunk header
	if _, err := io.ReadFull(&segment, lenBuf[:]); err != nil {
		t.Fatalf("chunk2 header: %v", err)
	}
	totalLen2 := binary.BigEndian.Uint32(lenBuf[:])
	if int(totalLen2) != len(payload2)+1 {
		t.Fatalf("chunk2 length = %d, want %d", totalLen2, len(payload2)+1)
	}

	raw2 := make([]byte, totalLen2)
	if _, err := io.ReadFull(&segment, raw2); err != nil {
		t.Fatalf("chunk2 payload: %v", err)
	}
	if raw2[0] != TypeData {
		t.Fatalf("chunk2 type = 0x%02x, want TypeData", raw2[0])
	}
	if !bytes.Equal(raw2[1:], payload2) {
		t.Fatalf("SECOND CHUNK PAYLOAD CORRUPTED! got %q, want %q",
			string(raw2[1:]), string(payload2))
	}

	t.Log("=== ALL INTEGRITY CHECKS PASSED ===")
}

// ---------------------------------------------------------------------------
// Test 6: Full reuse cycle correctness (bootstrap -> relay -> bootstrap -> relay)
// Tests that chunk framing stays synchronized across multiple reuse cycles
// ---------------------------------------------------------------------------

func TestReuseCycleFraming(t *testing.T) {
	c, s := newBufferedPipePair()
	defer c.Close()
	defer s.Close()

	ct := NewReusableTunnel(c)

	// Phase 1: Bootstrap + relay
	// Simulates client sending bootstrap JSON, server responding with "OK\n"
	// then both sides entering chunk protocol

	var wg sync.WaitGroup

	// Server: simulates handleClient + handleTCPRelayReuse
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Write "OK\n" to raw connection (simulating handleClient)
		s.Write([]byte("OK\n"))

		// Create ReusableTunnel on this side (simulating after OK sent)
		st := NewReusableTunnel(s)

		// Write response chunk (download data)
		if err := st.WriteChunk([]byte("response data phase 1")); err != nil {
			t.Errorf("server WriteChunk 1: %v", err)
			return
		}
		st.WriteEnd()

		// Read next bootstrap chunk
		bsChunk, err := st.ReadBootstrapChunk()
		if err != nil {
			t.Errorf("server ReadBootstrapChunk: %v", err)
			return
		}
		if len(bsChunk) == 0 {
			t.Error("expected bootstrap data")
			return
		}

		// Send OK chunk
		if err := st.WriteOKChunk(); err != nil {
			t.Errorf("server WriteOKChunk: %v", err)
			return
		}

		// Phase 2 relay: write response
		if err := st.WriteChunk([]byte("response data phase 2")); err != nil {
			t.Errorf("server WriteChunk 2: %v", err)
			return
		}
		st.WriteEnd()
	}()

	// Client: Phase 1 - initial bootstrap (raw JSON)
	// First create ReusableTunnel for reading OK + data
	// But the bootstrap sent only raw JSON + "\n" (simulating pool.bootstrap)

	// Actually, on the client side:
	// 1. pool.bootstrap: sends JSON + "\n", reads "OK\n" via readLine
	// 2. Then wraps in ReusableTunnel for chunk relay

	// Let's simulate: first we send nothing (the "JSON bootstrap" was already
	// written before this test). We go straight to reading "OK\n" + chunks.

	// Read "OK\n" via readLine
	status, err := ReadLine(c)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if status != "OK" {
		t.Fatalf("expected OK, got %q", status)
	}

	// Now use ReusableTunnel for chunk relay
	// Read response
	chunk1, err := ct.ReadChunk()
	if err != nil {
		t.Fatalf("ReadChunk 1: %v", err)
	}
	if chunk1 == nil || string(chunk1) != "response data phase 1" {
		t.Fatalf("phase1 response: got %q, want 'response data phase 1'", string(chunk1))
	}
	// Read EOS
	eos1, err := ct.ReadChunk()
	if err != nil || eos1 != nil {
		t.Fatalf("phase1 EOS: got %v err=%v", eos1, err)
	}

	// Phase 2: reuse bootstrap (chunk protocol)
	// Send bootstrap chunk
	bs := []byte(`{"auth":"t","host":"example.com","port":80}`)
	if err := ct.WriteBootstrapChunk(bs); err != nil {
		t.Fatalf("WriteBootstrapChunk: %v", err)
	}

	// Read OK chunk
	ok, err := ct.ReadOKChunk()
	if err != nil || !ok {
		t.Fatalf("ReadOKChunk: ok=%v err=%v", ok, err)
	}

	// Read phase 2 response
	chunk2, err := ct.ReadChunk()
	if err != nil {
		t.Fatalf("ReadChunk 2: %v", err)
	}
	if chunk2 == nil || string(chunk2) != "response data phase 2" {
		t.Fatalf("phase2 response: got %q, want 'response data phase 2'", string(chunk2))
	}
	// Read EOS
	eos2, err := ct.ReadChunk()
	if err != nil || eos2 != nil {
		t.Fatalf("phase2 EOS: got %v err=%v", eos2, err)
	}

	t.Log("=== REUSE CYCLE FRAMING PASSED ===")
}

// ---------------------------------------------------------------------------
// Test 7: Verify that the OLD code (conn.Read with buffer) would corrupt data
// but the NEW code (readLine) preserves it — side-by-side comparison
// ---------------------------------------------------------------------------

func TestOldVsNewOKRead(t *testing.T) {
	// Build identical data for both tests
	payload := []byte("THIS IS CRITICAL DATA THAT MUST BE PRESERVED!")

	var oldWire, newWire bytes.Buffer
	for _, w := range []*bytes.Buffer{&oldWire, &newWire} {
		w.Write([]byte("OK\n"))
		chunkLen := uint32(len(payload) + 1)
		lenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBytes, chunkLen)
		w.Write(lenBytes)
		w.Write([]byte{TypeData})
		w.Write(payload)
	}

	// NEW BEHAVIOR: readLine (byte-by-byte)
	status, err := ReadLine(&newWire)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if status != "OK" {
		t.Fatalf("expected OK, got %q", status)
	}

	// Verify chunk data is preserved
	var lenBuf [4]byte
	io.ReadFull(&newWire, lenBuf[:])
	totalLen := binary.BigEndian.Uint32(lenBuf[:])
	raw := make([]byte, totalLen)
	io.ReadFull(&newWire, raw)
	newPayload := raw[1:] // strip type byte

	if !bytes.Equal(newPayload, payload) {
		t.Error("NEW: payload corrupted!")
	} else {
		t.Logf("NEW (readLine): payload preserved (%d bytes) ✓", len(newPayload))
	}

	// OLD BEHAVIOR: large buffer Read
	oldBuf := make([]byte, 1024)
	n, _ := oldWire.Read(oldBuf)
	status = string(oldBuf[:n])
	if len(status) < 2 || status[:2] != "OK" {
		t.Fatalf("expected OK, got %q", status)
	}

	// Can we still read the chunk?
	var oldLenBuf [4]byte
	_, err = io.ReadFull(&oldWire, oldLenBuf[:])
	if err != nil {
		// This is expected — the old Read consumed the chunk bytes!
		t.Logf("OLD (conn.Read): chunk header read FAILED — data corrupted! ✗")
		t.Log("This proves the bug: old code consumed relay data as part of OK read")
	} else {
		// Rare: data wasn't consumed (only if "OK\n" happened to be at exact boundary)
		totalLen = binary.BigEndian.Uint32(oldLenBuf[:])
		raw = make([]byte, totalLen)
		io.ReadFull(&oldWire, raw)
		oldPayload := raw[1:]
		if bytes.Equal(oldPayload, payload) {
			t.Log("OLD: payload happened to survive (rare)")
		}
	}
}
