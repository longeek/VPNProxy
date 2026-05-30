package tunnel

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// bufferedPipe is a simple in-memory connection that buffers writes and
// delivers them on reads, avoiding the synchronous blocking behavior of
// net.Pipe. Useful for testing chunk-based protocols without deadlocks.
type bufferedPipe struct {
	readMu   sync.Mutex
	writeMu  sync.Mutex
	cond     *sync.Cond
	buf      []byte
	closed   bool
	otherEnd *bufferedPipe // peer reference for full-duplex
	readDeadline time.Time
}

func newBufferedPipePair() (*bufferedPipe, *bufferedPipe) {
	a := &bufferedPipe{}
	b := &bufferedPipe{}
	a.cond = sync.NewCond(&a.readMu)
	b.cond = sync.NewCond(&b.readMu)
	a.otherEnd = b
	b.otherEnd = a
	return a, b
}

func (p *bufferedPipe) Read(b []byte) (int, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()

	for len(p.buf) == 0 && !p.closed {
		if !p.readDeadline.IsZero() && time.Now().After(p.readDeadline) {
			return 0, errors.New("timeout")
		}
		p.cond.Wait()
	}
	if len(p.buf) == 0 && p.closed {
		return 0, io.EOF
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

func (p *bufferedPipe) Write(b []byte) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	other := p.otherEnd
	if other == nil {
		return 0, errors.New("not connected")
	}

	other.readMu.Lock()
	other.buf = append(other.buf, b...)
	other.cond.Broadcast()
	other.readMu.Unlock()

	return len(b), nil
}

func (p *bufferedPipe) Close() error {
	p.readMu.Lock()
	p.closed = true
	p.cond.Broadcast()
	p.readMu.Unlock()

	// Signal the other end so blocked reads return EOF
	other := p.otherEnd
	if other != nil {
		other.readMu.Lock()
		other.closed = true
		other.cond.Broadcast()
		other.readMu.Unlock()
	}
	return nil
}

func (p *bufferedPipe) LocalAddr() net.Addr  { return dummyAddr{} }
func (p *bufferedPipe) RemoteAddr() net.Addr { return dummyAddr{} }
func (p *bufferedPipe) SetDeadline(t time.Time) error {
	p.SetReadDeadline(t)
	return nil
}
func (p *bufferedPipe) SetReadDeadline(t time.Time) error {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	p.readDeadline = t
	return nil
}
func (p *bufferedPipe) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "mem" }
func (dummyAddr) String() string  { return "test" }
