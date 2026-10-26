package obfsh

import (
	"fmt"
	"io"
	"net"

	"github.com/agnostic-t/neutrino-core/handshake"
	obfs "github.com/agnostic-t/neutrino-obfs/xobfs"
	algo "github.com/agnostic-t/neutrino-obfs/xobfs/algo"
)

var _ handshake.HandshakeHandler = &ObfsHandshaker{}

type ObfsHandshaker struct {
	ContinueJunk    bool
	Psk             []byte
	RotateSeconds   int64 // deprecated, ignored (kept for config compatibility)
	RotateJunkCound bool  // deprecated, ignored (kept for config compatibility)

	MinJunkPacks int
	MaxJunkPacks int
}

func NewObfsHandshaker(psk []byte, startJunk bool, rotateSeconds int64, rotateJunkCount bool, minJunkPacks, maxJunkPacks int) *ObfsHandshaker {
	return &ObfsHandshaker{
		Psk:             psk,
		ContinueJunk:    startJunk,
		RotateSeconds:   rotateSeconds,
		RotateJunkCound: rotateJunkCount,
		MinJunkPacks:    minJunkPacks,
		MaxJunkPacks:    maxJunkPacks,
	}
}

// junkBounds returns the configured [min,max] junk packet bounds, falling back
// to the original hardcoded 0..6 so that configs which do not set
// minJunkPacks/maxJunkPacks behave exactly like before.
func (h *ObfsHandshaker) junkBounds() (int64, int64) {
	minJ, maxJ := int64(h.MinJunkPacks), int64(h.MaxJunkPacks)
	if minJ == 0 && maxJ == 0 {
		return 0, 6
	}
	if minJ > maxJ {
		minJ, maxJ = maxJ, minJ
	}
	if minJ < 0 {
		minJ = 0
	}
	if maxJ < minJ {
		maxJ = minJ
	}
	return minJ, maxJ
}

// junkPrand returns the PRNG used to derive the junk packet count. It MUST be
// a value that is identical on both peers: the raw PSK (see FIX 1 above).
func (h *ObfsHandshaker) junkPrand() *algo.PrandState {
	return algo.InitPrandStateFromPSK(h.Psk)
}

func (h *ObfsHandshaker) WriteHandshake(w net.Conn, target, proto string) error {
	protoByte := make([]byte, 1)
	switch proto {
	case "tcp":
		protoByte[0] = 0x00
	case "udp":
		protoByte[0] = 0x01
	default:
		return fmt.Errorf("Unknown protocol: %s", proto)
	}

	obfsed, err := algo.Obfuscate(append(protoByte, []byte(target)...), h.Psk)
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
		prState := h.junkPrand()
		minJ, maxJ := h.junkBounds()
		junkN := prState.PrandInt(minJ, maxJ)

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

func (h *ObfsHandshaker) ReadHandshake(r net.Conn) (string, string, error) {
	if h.ContinueJunk {
		prState := h.junkPrand()
		minJ, maxJ := h.junkBounds()
		junkN := prState.PrandInt(minJ, maxJ)

		for range junkN {
			var header [4]byte
			if _, err := io.ReadFull(r, header[:]); err != nil {
				return "", "", err
			}

			frameLen, _, err := obfs.ObfsDecodeHeader(header, h.Psk)
			if err != nil {
				return "", "", err
			}

			junk := make([]byte, frameLen)
			if _, err := io.ReadFull(r, junk); err != nil {
				return "", "", err
			}
		}
	}

	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", "", err
	}

	frameLen, _, err := obfs.ObfsDecodeHeader(header, h.Psk)
	if err != nil {
		return "", "", err
	}

	data := make([]byte, frameLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", "", err
	}

	deob, err := algo.Deobfuscate(data, h.Psk)
	if err != nil {
		return "", "", err
	}

	var protoString string
	switch deob[0] {
	case 0x00:
		protoString = "tcp"
	case 0x01:
		protoString = "udp"
	default:
		return "", "", fmt.Errorf("Unknown protocol byte: %d", deob[0])
	}

	return protoString, string(deob[1:]), nil
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
