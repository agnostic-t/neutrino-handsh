package obfsh

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/agnostic-t/neutrino-core/handshake"
	obfs "github.com/agnostic-t/neutrino-obfs/xobfs"
	algo "github.com/agnostic-t/neutrino-obfs/xobfs/algo"
)

var _ handshake.HandshakeHandler = &ObfsHandshaker{}

type ObfsHandshaker struct {
	ContinueJunk    bool
	Psk             []byte
	RotateSeconds   int64
	RotateJunkCound bool
}

func timeferral_key(time, rotate_seconds int64) [32]byte {
	stepped := uint64(math.Floor(float64(time) / float64(rotate_seconds))) // 30 seconds step to rotate

	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, stepped)

	return sha256.Sum256(buf)
}

func NewObfsHandshaker(psk []byte, startJunk bool, rotateSeconds int64, rotateJunkCount bool, minJunkPacks, maxJunkPacks int) *ObfsHandshaker {
	return &ObfsHandshaker{
		Psk:             psk,
		ContinueJunk:    startJunk,
		RotateSeconds:   rotateSeconds,
		RotateJunkCound: rotateJunkCount,
	}
}

func (h *ObfsHandshaker) WriteHandshake(w net.Conn, target, proto string) error {
	if h.RotateSeconds != -1 && time.Now().Unix()%h.RotateSeconds == h.RotateSeconds-2 { // if 2 seconds reamains for new step
		// wait 2 seconds
		time.Sleep(time.Second * 2)
	}

	psk := make([]byte, len(h.Psk))
	copy(psk, h.Psk)

	if h.RotateSeconds != -1 {
		tkey := timeferral_key(time.Now().Unix(), h.RotateSeconds)
		for i := range len(h.Psk) {
			psk[i] ^= tkey[i%len(tkey)]
		}
	}

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
		var prState *algo.PrandState
		if h.RotateJunkCound {
			prState = algo.InitPrandStateFromPSK(psk)
		} else {
			prState = algo.InitPrandStateFromPSK(h.Psk)
		}

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

func (h *ObfsHandshaker) ReadHandshake(r net.Conn) (string, string, error) {
	if h.RotateSeconds != -1 && time.Now().Unix()%h.RotateSeconds == h.RotateSeconds-2 { // if 2 seconds reamains for new step
		// wait 2 seconds
		time.Sleep(time.Second * 2)
	}

	psk := make([]byte, len(h.Psk))
	copy(psk, h.Psk)

	if h.RotateSeconds != -1 {
		tkey := timeferral_key(time.Now().Unix(), h.RotateSeconds)
		for i := range len(h.Psk) {
			psk[i] ^= tkey[i%len(tkey)]
		}
	}

	if h.ContinueJunk {
		var prState *algo.PrandState
		if h.RotateJunkCound {
			prState = algo.InitPrandStateFromPSK(psk)
		} else {
			prState = algo.InitPrandStateFromPSK(h.Psk)
		}

		junkN := prState.PrandInt(0, 6)

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

	// fmt.Printf("got deobfuscated: %s\n", deob)
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
