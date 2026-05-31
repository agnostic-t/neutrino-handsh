package obfsh

import (
	"io"
	"net"

	"github.com/agnostic-t/neutrino-core/handshake"
	obfs "github.com/agnostic-t/neutrino-obfs/xobfs"
	algo "github.com/agnostic-t/neutrino-obfs/xobfs/algo"
)

var _ handshake.HandshakeHandler = &ObfsHandshaker{}

type ObfsHandshaker struct {
	ContinueJunk bool
	Psk          []byte
}

func NewObfsHandshaker(psk []byte, startJunk bool) *ObfsHandshaker {
	return &ObfsHandshaker{Psk: psk, ContinueJunk: startJunk}
}

func (h *ObfsHandshaker) WriteHandshake(w net.Conn, target string) error {
	obfsed, err := algo.Obfuscate([]byte(target), h.Psk)
	if err != nil {
		return err
	}

	encr_buff := make([]byte, 4+len(obfsed))
	header, err := obfs.ObfsEncodeHeader(uint16(len(obfsed)), h.Psk)
	if err != nil {
		return err
	}

	copy(encr_buff[:4], header[:])
	copy(encr_buff[4:], obfsed)

	if h.ContinueJunk {
		prState := algo.InitPrandStateFromPSK(h.Psk)
		junkN := prState.PrandInt(0, 6)

		for range junkN {
			j, err := algo.GenJitterUrand(10, 90)
			if err != nil {
				return err
			}

			chunk := make([]byte, 4+len(j))
			header, err := obfs.ObfsEncodeHeader(uint16(len(j)), h.Psk)
			if err != nil {
				return err
			}

			copy(chunk[:4], header[:])
			copy(chunk[4:], j)

			if _, err := w.Write(chunk); err != nil {
				return err
			}
		}
	}

	if _, err := w.Write(encr_buff); err != nil {
		return err
	}

	return nil
}

func (h *ObfsHandshaker) ReadHandshake(r net.Conn) (string, error) {

	if h.ContinueJunk {
		prState := algo.InitPrandStateFromPSK(h.Psk)
		junkN := prState.PrandInt(0, 6)

		for range junkN {
			var header [4]byte
			if _, err := io.ReadFull(r, header[:]); err != nil {
				return "", err
			}

			frameLen, _, err := obfs.ObfsDecodeHeader(header, h.Psk)
			if err != nil {
				return "", err
			}

			junk := make([]byte, frameLen)
			if _, err := io.ReadFull(r, junk); err != nil {
				return "", err
			}
		}
	}

	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", err
	}

	frameLen, _, err := obfs.ObfsDecodeHeader(header, h.Psk)
	if err != nil {
		return "", err
	}

	data := make([]byte, frameLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", err
	}

	deob, err := algo.Deobfuscate(data, h.Psk)
	if err != nil {
		return "", err
	}

	return string(deob), nil
}

func (h *ObfsHandshaker) Success(conn net.Conn) bool {
	obfsed, err := algo.Obfuscate([]byte("ok"), h.Psk)
	if err != nil {
		return false
	}

	encr_buff := make([]byte, 4+len(obfsed))
	header, err := obfs.ObfsEncodeHeader(uint16(len(obfsed)), h.Psk)
	if err != nil {
		return false
	}

	copy(encr_buff[:4], header[:])
	copy(encr_buff[4:], obfsed)

	if _, err := conn.Write(encr_buff); err != nil {
		return false
	}

	return true
}

func (h *ObfsHandshaker) Failure(conn net.Conn) bool {
	obfsed, err := algo.Obfuscate([]byte("failed"), h.Psk)
	if err != nil {
		return false
	}

	encr_buff := make([]byte, 4+len(obfsed))
	header, err := obfs.ObfsEncodeHeader(uint16(len(obfsed)), h.Psk)
	if err != nil {
		return false
	}

	copy(encr_buff[:4], header[:])
	copy(encr_buff[4:], obfsed)

	if _, err := conn.Write(encr_buff); err != nil {
		return false
	}

	return true
}

func (h *ObfsHandshaker) ReadStatus(conn net.Conn) bool {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return false
	}

	frameLen, _, err := obfs.ObfsDecodeHeader(header, h.Psk)
	if err != nil {
		return false
	}

	data := make([]byte, frameLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		return false
	}

	deob, err := algo.Deobfuscate(data, h.Psk)
	if err != nil {
		return false
	}

	return string(deob) == "ok"
}
