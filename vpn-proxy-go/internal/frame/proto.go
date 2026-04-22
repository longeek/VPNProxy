package frame

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
)

func ReadFromStream(r io.Reader) (*UdpFrame, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != Version {
		return nil, ErrBadVersion
	}
	nlen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if nlen == 0 || nlen > 1024 {
		return nil, ErrBadHostLen
	}
	hostBuf := make([]byte, nlen)
	if _, err := io.ReadFull(r, hostBuf); err != nil {
		return nil, err
	}
	host := string(hostBuf)
	portDlen := make([]byte, 4)
	if _, err := io.ReadFull(r, portDlen); err != nil {
		return nil, err
	}
	port := binary.BigEndian.Uint16(portDlen[0:2])
	dlen := int(binary.BigEndian.Uint16(portDlen[2:4]))
	if dlen > 65535 {
		return nil, ErrBadPayloadLen
	}
	data := make([]byte, dlen)
	if dlen > 0 {
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
	}
	return &UdpFrame{Host: host, Port: port, Data: data}, nil
}

func WriteToStream(w io.Writer, host string, port uint16, data []byte) error {
	packed := Pack(host, port, data)
	_, err := w.Write(packed)
	return err
}

func SocksUdpParseRequest(packet []byte) (host string, port uint16, payload []byte, err error) {
	if len(packet) < 10 {
		return "", 0, nil, errors.New("short socks udp packet")
	}
	if packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return "", 0, nil, errors.New("bad socks udp header")
	}
	atyp := packet[3]
	off := 4
	switch atyp {
	case 0x01:
		if len(packet) < off+4+2 {
			return "", 0, nil, errors.New("short ipv4")
		}
		host = net.IP(packet[off:off+4]).To4().String()
		off += 4
	case 0x03:
		ln := int(packet[off])
		off++
		if len(packet) < off+ln+2 {
			return "", 0, nil, errors.New("short domain")
		}
		host = string(packet[off:off+ln])
		off += ln
	case 0x04:
		if len(packet) < off+16+2 {
			return "", 0, nil, errors.New("short ipv6")
		}
		host = net.IP(packet[off:off+16]).To16().String()
		off += 16
	default:
		return "", 0, nil, errors.New("unsupported atyp")
	}
	if len(packet) < off+2 {
		return "", 0, nil, errors.New("short port")
	}
	port = binary.BigEndian.Uint16(packet[off:off+2])
	payload = packet[off+2:]
	return host, port, payload, nil
}

func SocksUdpBuildReply(host string, port uint16, data []byte) []byte {
	ip := net.ParseIP(host)
	if ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf := make([]byte, 4+4+2+len(data))
			buf[0] = 0x00; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x01
			copy(buf[4:8], v4)
			binary.BigEndian.PutUint16(buf[8:10], port)
			copy(buf[10:], data)
			return buf
		}
		if v6 := ip.To16(); v6 != nil {
			buf := make([]byte, 4+16+2+len(data))
			buf[0] = 0x00; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x04
			copy(buf[4:20], v6)
			binary.BigEndian.PutUint16(buf[20:22], port)
			copy(buf[22:], data)
			return buf
		}
	}
	hb := []byte(host)
	buf := make([]byte, 4+1+len(hb)+2+len(data))
	buf[0] = 0x00; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x03
	buf[4] = byte(len(hb))
	copy(buf[5:5+len(hb)], hb)
	binary.BigEndian.PutUint16(buf[5+len(hb):5+len(hb)+2], port)
	copy(buf[5+len(hb)+2:], data)
	return buf
}

func ParseHTTPConnectTarget(header []byte) (host string, port uint16, err error) {
	firstLine := bytes.SplitN(header, []byte("\r\n"), 2)[0]
	s := string(firstLine)
	parts := strings.SplitN(s, " ", 3)
	if len(parts) < 3 || !strings.EqualFold(parts[0], "CONNECT") {
		return "", 0, errors.New("not CONNECT")
	}
	target := parts[1]
	sep := strings.LastIndex(target, ":")
	if sep < 0 {
		return "", 0, errors.New("bad target")
	}
	host = target[:sep]
	p, err2 := strconv.ParseUint(target[sep+1:], 10, 16)
	if err2 != nil {
		return "", 0, errors.New("bad port")
	}
	port = uint16(p)
	return host, port, nil
}

func CheckHTTPBasicAuth(header []byte, user, pass string) bool {
	lines := bytes.Split(header, []byte("\r\n"))
	for _, line := range lines {
		lower := bytes.ToLower(line)
		if bytes.HasPrefix(lower, []byte("proxy-authorization:")) {
			val := string(bytes.TrimLeft(line[len("proxy-authorization:"):], " "))
			if strings.HasPrefix(strings.ToLower(val), "basic ") {
				b64 := strings.TrimSpace(val[6:])
				decoded, err := base64.StdEncoding.DecodeString(b64)
				if err != nil {
					return false
				}
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 && parts[0] == user && parts[1] == pass {
					return true
				}
			}
			return false
		}
	}
	return false
}

func ParseTCPLineTarget(line []byte) (host string, port uint16, err error) {
	s := strings.TrimSpace(string(line))
	if s == "" {
		return "", 0, errors.New("empty target")
	}
	if sep := strings.LastIndex(s, ":"); sep >= 0 {
		host = strings.TrimSpace(s[:sep])
		ps := strings.TrimSpace(s[sep+1:])
		if host == "" {
			return "", 0, errors.New("empty host")
		}
		p, e := strconv.ParseUint(ps, 10, 16)
		if e != nil || p == 0 {
			return "", 0, errors.New("bad port")
		}
		port = uint16(p)
		return host, port, nil
	}
	parts := strings.Fields(s)
	if len(parts) == 2 {
		host = parts[0]
		p, e := strconv.ParseUint(parts[1], 10, 16)
		if e != nil || p == 0 {
			return "", 0, errors.New("bad port")
		}
		port = uint16(p)
		return host, port, nil
	}
	return "", 0, errors.New("expected host:port")
}