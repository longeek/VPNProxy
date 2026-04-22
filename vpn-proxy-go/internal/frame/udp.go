package frame

import (
	"encoding/binary"
	"errors"
)

const Version = 1

var (
	ErrBadVersion     = errors.New("bad udp frame version")
	ErrBadHostLen     = errors.New("bad udp frame host length")
	ErrBadPayloadLen  = errors.New("bad udp frame payload length")
	ErrBufferTooShort = errors.New("buffer too short")
)

type UdpFrame struct {
	Host string
	Port uint16
	Data []byte
}

func Pack(host string, port uint16, data []byte) []byte {
	hb := []byte(host)
	buf := make([]byte, 4+len(hb)+4+len(data))
	buf[0] = Version
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(hb)))
	copy(buf[4:4+len(hb)], hb)
	off := 4 + len(hb)
	binary.BigEndian.PutUint16(buf[off:off+2], port)
	binary.BigEndian.PutUint16(buf[off+2:off+4], uint16(len(data)))
	copy(buf[off+4:], data)
	return buf
}

func ReadFromSlice(buf []byte) (*UdpFrame, int, error) {
	if len(buf) < 4 {
		return nil, 0, ErrBufferTooShort
	}
	if buf[0] != Version {
		return nil, 0, ErrBadVersion
	}
	nlen := int(binary.BigEndian.Uint16(buf[2:4]))
	if nlen == 0 || nlen > 1024 {
		return nil, 0, ErrBadHostLen
	}
	if len(buf) < 4+nlen+4 {
		return nil, 0, ErrBufferTooShort
	}
	host := string(buf[4:4+nlen])
	off := 4 + nlen
	port := binary.BigEndian.Uint16(buf[off:off+2])
	dlen := int(binary.BigEndian.Uint16(buf[off+2:off+4]))
	if dlen > 65535 {
		return nil, 0, ErrBadPayloadLen
	}
	if len(buf) < off+4+dlen {
		return nil, 0, ErrBufferTooShort
	}
	data := make([]byte, dlen)
	copy(data, buf[off+4:off+4+dlen])
	wireLen := off + 4 + dlen
	return &UdpFrame{Host: host, Port: port, Data: data}, wireLen, nil
}