package basic

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/agnostic-t/neutrino-core/handshake"
)

var _ handshake.HandshakeHandler = &BasicHandshaker{}

type BasicHandshaker struct{}

func (h *BasicHandshaker) WriteHandshake(w net.Conn, target string, proto string) error {
	targetBytes := []byte(target)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(targetBytes)))

	protoByte := make([]byte, 1)

	switch proto {
	case "tcp":
		protoByte[0] = 0x00
	case "udp":
		protoByte[0] = 0x01
	default:
		return fmt.Errorf("Invalid protocol: %s", proto)
	}

	if _, err := w.Write(lenBuf); err != nil {
		return err
	}

	if _, err := w.Write(protoByte); err != nil {
		return err
	}

	_, err := w.Write(targetBytes)
	return err
}

func (h *BasicHandshaker) ReadHandshake(r net.Conn) (string, string, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return "", "", err
	}
	targetLen := binary.BigEndian.Uint16(lenBuf)

	protoBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, protoBuf); err != nil {
		return "", "", err
	}

	targetBuf := make([]byte, targetLen)
	if _, err := io.ReadFull(r, targetBuf); err != nil {
		return "", "", err
	}

	var protoStr string
	if protoBuf[0] == 0x00 {
		protoStr = "tcp"
	} else if protoBuf[0] == 0x01 {
		protoStr = "udp"
	} else {
		return "", "", fmt.Errorf("Unknown protocol type: %d", protoBuf[0])
	}

	return protoStr, string(targetBuf), nil
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
