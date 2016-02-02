package dns

import (
	"bytes"
	"errors"
	"math/rand"
	"strings"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine/socket"
)

// DNS RFC: http://www.rfc-editor.org/rfc/rfc1035.txt

const (
	openDNSSrv1 = `208.67.222.222:53`
	openDNSSrv2 = `208.67.220.220:53`
)

var (
	firstDNS = true

	// ErrNoAnswer is returned when the DNS query returned no answer section.
	ErrNoAnswer = errors.New(`DNS query returned no answer`)

	// ErrInvalidAnswer is returned if the DNS answer could not be parsed.
	ErrInvalidAnswer = errors.New(`DNS query returned invalid answer`)
)

// LookupCNAME does a CNAME lookup on the specified host
func LookupCNAME(ctx context.Context, host string) (cname string, err error) {
	conn, err := socket.Dial(ctx, "udp", nextDNSServer())
	if err != nil {
		return "", err
	}
	defer conn.Close()

	q := packCNAME(host)
	_, err = conn.Write(q)
	if err != nil {
		return "", err
	}

	var in [512]byte
	_, err = conn.Read(in[:])
	if err != nil {
		return "", err
	}

	return parseCNAMEAnswer(in[:])
}

func nextDNSServer() string {
	// This is not threadsafe, but it doesn't have to be
	addr := openDNSSrv2
	if firstDNS {
		addr = openDNSSrv1
	}
	firstDNS = !firstDNS
	return addr
}

func decodePointer(p []byte) (off int, isPtr bool) {
	if len(p) >= 2 && (p[0]&0xC0) == 0xC0 {
		n := uint(p[0]&0x3F)<<8 | uint(p[1]&0xFF)
		return int(n), true
	}
	return 0, false
}

func readName(b []byte, off int) (name string, offOut int) {
	var parts []string
	seenPtr := false
	for {
		label, newOff, eof, isPtr := readLabel(b, off)
		if isPtr {
			if !seenPtr {
				offOut = off + 2
			}
			seenPtr = true
		}
		if label != "" {
			parts = append(parts, label)
		}
		if eof {
			if !seenPtr {
				offOut = off + 1
			}
			break
		}
		off = newOff
	}

	name = strings.Join(parts, `.`)

	return
}

func readLabel(b []byte, off int) (label string, newOff int, eof, isPtr bool) {
	if off, ok := decodePointer(b[off:]); ok {
		return "", off, false, true
	}
	c := int(b[off])
	if c == 0 {
		return "", 0, true, false
	}
	return string(b[off+1 : off+1+c]), off + c + 1, false, false
}

const (
	opQUERY  byte = 0
	opIQUERY      = 1
	opSTATUS      = 2
)

const (
	qtypeA     uint16 = 1
	qtypeNS           = 2
	qtypeCNAME        = 5
	qtypeSOA          = 6
	qtypeWKS          = 11
	qtypePTR          = 12
	qtypeMX           = 15
	qtypeSRV          = 33
	qtypeA6           = 38
	qtypeANY          = 255
)

const (
	classINET = 1
)

type dnsHeader struct {
	ID      uint16
	QR      byte // 1 bit
	OPCODE  byte // 4 bit
	AA      byte // 1 bit
	TC      byte // 1 bit
	RD      byte // 1 bit
	RA      byte // 1 bit
	r1      byte // 1 bit
	r2      byte // 1 bit
	r3      byte // 1 bit
	RCODE   byte // 4 bit
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

func (h *dnsHeader) setID() {
	h.ID = uint16(rand.Int()) ^ uint16(time.Now().Nanosecond())
}

func (h *dnsHeader) unpack(b []byte) bool {
	if len(b) < 12 {
		return false
	}
	h.ID = uint16(b[0])<<8 | uint16(b[1])&0xFF
	h.QR = (b[2] & 0x80) >> 7
	h.OPCODE = (b[2] & 0x78) >> 3
	h.AA = (b[2] & 0x4) >> 2
	h.TC = (b[2] & 0x2) >> 1
	h.RD = (b[2] & 0x1)
	h.RA = (b[3] & 0x80) >> 7
	h.RCODE = (b[3] & 0xF)
	h.QDCOUNT = uint16(b[4])<<8 | uint16(b[5])&0xFF
	h.ANCOUNT = uint16(b[6])<<8 | uint16(b[7])&0xFF
	h.NSCOUNT = uint16(b[8])<<8 | uint16(b[9])&0xFF
	h.ARCOUNT = uint16(b[10])<<8 | uint16(b[11])&0xFF

	return true
}

type packer struct {
	bytes.Buffer
}

func (p *packer) writeUInt16(q uint16) {
	p.WriteByte(byte(q >> 8))
	p.WriteByte(byte(q & 0xFF))
}

func (p *packer) writeHeader(h dnsHeader) {
	var b [12]byte
	b[0] = byte(h.ID >> 8)
	b[1] = byte(h.ID & 0xFF)
	b[2] |= (h.QR & 0x1) << 7
	b[2] |= (h.OPCODE & 0xF) << 3
	b[2] |= (h.AA & 0x1) << 2
	b[2] |= (h.TC & 0x1) << 1
	b[2] |= (h.RD & 0x1)
	b[3] |= (h.RA & 0x1) << 7
	b[3] |= (h.RCODE & 0xF)
	b[4] = byte(h.QDCOUNT >> 8)
	b[5] = byte(h.QDCOUNT & 0xFF)
	b[6] = byte(h.ANCOUNT >> 8)
	b[7] = byte(h.ANCOUNT & 0xFF)
	b[8] = byte(h.NSCOUNT >> 8)
	b[9] = byte(h.NSCOUNT & 0xFF)
	b[10] = byte(h.ARCOUNT >> 8)
	b[11] = byte(h.ARCOUNT & 0xFF)

	p.Write(b[:])
}

func (p *packer) encodeName(name string) {
	a := strings.Split(name, `.`)
	for _, v := range a {
		p.WriteByte(byte(len(v)))
		for _, c := range v {
			p.WriteByte(byte(c))
		}
	}
	p.WriteByte(0x0)
}

func packCNAME(host string) []byte {
	// Pack DNS header
	var h dnsHeader
	h.setID()
	h.RD = 1
	h.QDCOUNT = 1

	var p packer
	p.writeHeader(h)
	p.encodeName(host) // QNAME
	p.writeUInt16(qtypeCNAME)
	p.writeUInt16(classINET)

	return p.Bytes()
}

func parseCNAMEAnswer(b []byte) (string, error) {
	var h dnsHeader
	if !h.unpack(b) {
		return "", ErrInvalidAnswer
	}

	// Check answer bit and count.
	if h.QR != 1 {
		return "", ErrInvalidAnswer
	}
	if h.ANCOUNT != 1 {
		return "", ErrNoAnswer
	}

	// Question section.
	_, off := readName(b, 12) // QNAME
	off += 4                  // skip QTYPE + QCLASS

	// Answer section.
	_, off = readName(b, off)              // NAME
	if b[off] != 0x0 || b[off+1] != 0x05 { // TYPE=CNAME
		return "", ErrInvalidAnswer
	}
	off += 2
	if b[off] != 0x0 || b[off+1] != 0x01 { // CLASS=INET
		return "", ErrInvalidAnswer
	}
	off += 2
	off += 4                      // skip TTL
	off += 2                      // skip RDLENGTH
	name, off := readName(b, off) // RDATA

	return name, nil
}
