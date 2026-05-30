package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// Chunk types for the reuse protocol (1 byte each).
const (
	TypeData      byte = 0x00 // relay data chunk
	TypeBootstrap byte = 0x01 // bootstrap JSON for new target
	TypeOK        byte = 0x02 // OK acknowledgment
)

// ReusableTunnel wraps a TLS/raw connection with a length-prefixed chunk
// protocol that allows the connection to be reused across multiple relay
// sessions without closing.
//
// Wire format:
//
//	[4-byte total_length (big-endian, includes type + payload)]
//	[1-byte type]                           (only when total_length > 0)
//	[payload bytes]                         (only when total_length > 0)
//	total_length == 0  → end-of-stream marker (no type, no payload)
type ReusableTunnel struct {
	conn net.Conn
	br   *countingReader
}

// countingReader wraps an io.Reader with a byte counter for diagnostics.
type countingReader struct {
	r    io.Reader
	total int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.total += int64(n)
	return n, err
}

// NewReusableTunnel wraps a connection for chunk-based communication.
// The connection must already be established and authenticated.
func NewReusableTunnel(conn net.Conn) *ReusableTunnel {
	return &ReusableTunnel{
		conn: conn,
		br:   &countingReader{r: conn},
	}
}

// Conn returns the underlying connection.
func (rt *ReusableTunnel) Conn() net.Conn {
	return rt.conn
}

// Close closes the underlying connection.
func (rt *ReusableTunnel) Close() error {
	return rt.conn.Close()
}

// ReadChunk reads one chunk from the tunnel. Returns:
//   - (payload, nil) for a data chunk (type byte stripped)
//   - (nil, nil) for end-of-stream marker
//   - (nil, err) on read error
func (rt *ReusableTunnel) ReadChunk() ([]byte, error) {
	chunkType, payload, err := rt.readChunkTyped()
	if err != nil {
		return nil, err
	}
	if chunkType == 0 && payload == nil {
		return nil, nil // end-of-stream
	}
	return payload, nil
}

// readChunkTyped reads a chunk and returns (type, payload, error).
func (rt *ReusableTunnel) readChunkTyped() (byte, []byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(rt.br, lenBuf[:]); err != nil {
		return 0, nil, err
	}
	totalLen := binary.BigEndian.Uint32(lenBuf[:])
	if totalLen == 0 {
		return 0, nil, nil // end-of-stream
	}

	raw := make([]byte, totalLen)
	if _, err := io.ReadFull(rt.br, raw); err != nil {
		return 0, nil, err
	}

	if totalLen == 0 {
		return 0, nil, nil
	}
	return raw[0], raw[1:], nil
}

// WriteChunk writes a DATA-type chunk. The payload is prefixed with the
// length header and type byte. Returns an error only on write failure.
func (rt *ReusableTunnel) WriteChunk(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)+1)) // +1 for type
	if _, err := rt.conn.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := rt.conn.Write([]byte{TypeData}); err != nil {
		return err
	}
	if _, err := rt.conn.Write(data); err != nil {
		return err
	}
	return nil
}

// WriteEnd sends the end-of-stream marker (zero-length packet).
func (rt *ReusableTunnel) WriteEnd() error {
	_, err := rt.conn.Write([]byte{0, 0, 0, 0})
	return err
}

// WriteBootstrapChunk sends a BOOTSTRAP-type chunk with the given JSON payload.
func (rt *ReusableTunnel) WriteBootstrapChunk(jsonPayload []byte) error {
	// Encode as: [4-byte len][type=Bootstrap][json payload]
	totalLen := uint32(len(jsonPayload) + 1) // +1 for type byte
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], totalLen)
	if _, err := rt.conn.Write(header[:]); err != nil {
		return err
	}
	if _, err := rt.conn.Write([]byte{TypeBootstrap}); err != nil {
		return err
	}
	if _, err := rt.conn.Write(jsonPayload); err != nil {
		return err
	}
	return nil
}

// ReadBootstrapChunk reads a chunk and returns its payload if it is a
// BOOTSTRAP type. Returns error if the chunk is of a different type.
func (rt *ReusableTunnel) ReadBootstrapChunk() ([]byte, error) {
	chunkType, payload, err := rt.readChunkTyped()
	if err != nil {
		return nil, err
	}
	if chunkType == 0 && payload == nil {
		return nil, fmt.Errorf("unexpected end-of-stream while reading bootstrap")
	}
	if chunkType != TypeBootstrap {
		return nil, fmt.Errorf("expected bootstrap chunk (type=0x%02x), got type=0x%02x", TypeBootstrap, chunkType)
	}
	return payload, nil
}

// WriteOKChunk sends an OK acknowledgment chunk.
func (rt *ReusableTunnel) WriteOKChunk() error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len("OK")+1)) // +1 for type
	if _, err := rt.conn.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := rt.conn.Write([]byte{TypeOK}); err != nil {
		return err
	}
	if _, err := rt.conn.Write([]byte("OK")); err != nil {
		return err
	}
	return nil
}

// ReadOKChunk reads a chunk and returns true if it is an OK chunk.
// Returns false + error if the chunk is of a different type or an error occurs.
func (rt *ReusableTunnel) ReadOKChunk() (bool, error) {
	chunkType, payload, err := rt.readChunkTyped()
	if err != nil {
		return false, err
	}
	if chunkType == 0 && payload == nil {
		return false, fmt.Errorf("unexpected end-of-stream while reading OK")
	}
	if chunkType != TypeOK {
		return false, fmt.Errorf("expected OK chunk (type=0x%02x), got type=0x%02x, payload=%q", TypeOK, chunkType, string(payload))
	}
	if string(payload) != "OK" {
		return false, fmt.Errorf("expected OK payload, got %q", string(payload))
	}
	return true, nil
}

// StreamBytes returns total bytes read from the underlying connection.
func (rt *ReusableTunnel) StreamBytes() int64 {
	return rt.br.total
}

// ---------------------------------------------------------------------------
// WriteBootstrapChunk / ReadBootstrapChunk / WriteOKChunk / ReadOKChunk
// convenience wrappers for interface compatibility in tests
// ---------------------------------------------------------------------------

// WriteBootstrapChunk is a package-level wrapper.
func WriteBootstrapChunk(rt *ReusableTunnel, data []byte) error {
	return rt.WriteBootstrapChunk(data)
}

// ReadBootstrapChunk is a package-level wrapper.
func ReadBootstrapChunk(rt *ReusableTunnel) ([]byte, error) {
	return rt.ReadBootstrapChunk()
}

// WriteOKChunk is a package-level wrapper.
func WriteOKChunk(rt *ReusableTunnel) error {
	return rt.WriteOKChunk()
}

// ReadOKChunk is a package-level wrapper.
func ReadOKChunk(rt *ReusableTunnel) (bool, error) {
	return rt.ReadOKChunk()
}

// ---------------------------------------------------------------------------
// RelayBidirectionalReuse (client side)
// ---------------------------------------------------------------------------

// RelayBidirectionalReuse relays data bidirectionally between a SOCKS5 client
// and a ReusableTunnel using the chunk protocol. After the relay completes,
// the tunnel remains open and can be reused for subsequent relays.
//
// Upload direction (client → target):
//   - Reads from SOCKS5 client, writes DATA chunks to tunnel
//   - Sends end-of-stream marker when client upload is complete
//
// Download direction (target → client):
//   - Reads DATA chunks from tunnel
//   - Writes to SOCKS5 client
//   - Stops when end-of-stream marker is received
func RelayBidirectionalReuse(client net.Conn, rt *ReusableTunnel, upStats, downStats *uint64) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Upload: client → rt (DATA chunks)
	go func() {
		defer wg.Done()
		buf := getRelayBuf()
		defer putRelayBuf(buf)
		var total uint64
		for {
			n, err := client.Read(buf)
			if n > 0 {
				if wErr := rt.WriteChunk(buf[:n]); wErr != nil {
					break
				}
				total += uint64(n)
			}
			if err != nil {
				break
			}
		}
		rt.WriteEnd()
		if upStats != nil {
			atomic.AddUint64(upStats, total)
		}
	}()

	// Download: rt → client
	go func() {
		defer wg.Done()
		var total uint64
		for {
			chunkType, payload, err := rt.readChunkTyped()
			if err != nil || chunkType == 0 && payload == nil {
				break
			}
			if chunkType != TypeData {
				break
			}
			if len(payload) > 0 {
				if _, wErr := client.Write(payload); wErr != nil {
					break
				}
				total += uint64(len(payload))
			}
		}
		client.Close()
		if downStats != nil {
			atomic.AddUint64(downStats, total)
		}
	}()

	wg.Wait()
}

// ---------------------------------------------------------------------------
// RelayTCPServerReuse (server side)
// ---------------------------------------------------------------------------

// RelayTCPServerReuse relays data bidirectionally between a ReusableTunnel
// and a target (backend) connection using the chunk protocol. After the
// relay completes, the tunnel remains open and ready for the next bootstrap.
//
// Upload direction (client → target):
//   - Reads DATA chunks from tunnel
//   - Writes to target connection
//   - On end-of-stream, closes the target (signals download completion)
//
// Download direction (target → client):
//   - Reads from target, writes DATA chunks to tunnel
//   - On target EOF, sends end-of-stream marker
func RelayTCPServerReuse(rt *ReusableTunnel, target net.Conn, stats *SessionStats) {
	bufUp := getRelayBuf()
	bufDown := getRelayBuf()
	done := make(chan struct{}, 2)

	// Upload: rt → target (client data → backend server)
	go func() {
		defer putRelayBuf(bufUp)
		defer func() {
			target.Close()
			done <- struct{}{}
		}()
		for {
			chunkType, payload, err := rt.readChunkTyped()
			if err != nil || chunkType == 0 && payload == nil {
				return
			}
			if chunkType != TypeData {
				return
			}
			if len(payload) > 0 {
				if _, werr := target.Write(payload); werr != nil {
					return
				}
				stats.UploadBytes.Add(uint64(len(payload)))
			}
		}
	}()

	// Download: target → rt (backend response → client)
	go func() {
		defer putRelayBuf(bufDown)
		defer func() {
			rt.WriteEnd()
			done <- struct{}{}
		}()
		for {
			n, err := target.Read(bufDown)
			if n > 0 {
				if werr := rt.WriteChunk(bufDown[:n]); werr != nil {
					return
				}
				stats.DownloadBytes.Add(uint64(n))
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	<-done
}
