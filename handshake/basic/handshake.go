package basic

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/agnostic-t/neutrino-core/handshake"
)

var _ handshake.HandshakeHandler = &BasicHandshaker{}

type BasicHandshaker struct{}

func (h *BasicHandshaker) WriteHandshake(w net.Conn, target string) error {
	targetBytes := []byte(target)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(targetBytes)))

	if _, err := w.Write(lenBuf); err != nil {
		return err
	}

	_, err := w.Write(targetBytes)
	return err
}

func (h *BasicHandshaker) ReadHandshake(r net.Conn) (string, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return "", err
	}
	targetLen := binary.BigEndian.Uint16(lenBuf)

	targetBuf := make([]byte, targetLen)
	if _, err := io.ReadFull(r, targetBuf); err != nil {
		return "", err
	}

	return string(targetBuf), nil
}

func (h *BasicHandshaker) Success(conn net.Conn) bool {
	conn.Write([]byte{0x00})
	return true
}

func (h *BasicHandshaker) Failure(conn net.Conn) bool {
	conn.Write([]byte{0x01})
	return true
}

func (h *BasicHandshaker) ReadStatus(conn net.Conn) bool {
	var buf [1]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		return false
	}

	return buf[0] == 0x00
}
