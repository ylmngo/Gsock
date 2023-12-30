package gsock

import (
	"errors"
	"io"
	"net"
)

const (
	TEXT_FRAME = 0b0000_0001
)

type Frame struct {
	Fin        bool
	Rsv1       bool
	Rsv2       bool
	Rsv3       bool
	Opcode     byte
	Mask       bool
	Payloadlen int
	MaskKey    [4]byte
	Payload    []byte
}

func buildFrame(conn net.Conn) (*Frame, error) {
	buff := make([]byte, 2)
	n, err := io.ReadFull(conn, buff)

	if err != nil {
		return nil, err
	}

	if n <= 0 {
		return nil, errors.New("insufficient data")
	}

	Fin := ((buff[0] & 0b1000_0000) == 0b1000_0000)
	Rsv1 := ((buff[0] & 0b0100_0000) == 0b0100_0000)
	Rsv2 := ((buff[0] & 0b0010_0000) == 0b0010_0000)
	Rsv3 := ((buff[0] & 0b0001_0000) == 0b0001_0000)
	Opcode := (buff[0] & TEXT_FRAME)
	Mask := (buff[1] & 0b1000_0000) == 0b1000_0000
	PayloadLen := int(buff[1] & 0b0111_1111)

	frame := Frame{
		Fin:        Fin,
		Rsv1:       Rsv1,
		Rsv2:       Rsv2,
		Rsv3:       Rsv3,
		Opcode:     Opcode,
		Mask:       Mask,
		Payloadlen: PayloadLen,
	}

	if Mask {
		maskKey := make([]byte, 4)
		io.ReadFull(conn, maskKey)
		frame.MaskKey = [4]byte(maskKey)
	}

	if Opcode == TEXT_FRAME {
		maskedPayload := make([]byte, PayloadLen)
		io.ReadFull(conn, maskedPayload)
		frame.Payload = decodePayload(maskedPayload, frame.MaskKey)
	}

	return &frame, nil
}

func decodePayload(data []byte, maskKey [4]byte) []byte {
	var payload []byte
	for i, b := range data {
		payload = append(payload, b^maskKey[i%4])
	}

	return payload
}

// Converts the frame to it's equivalent RFC format
func (frame *Frame) packFrame() []byte {
	header := make([]byte, 2)

	header[0] = 0b0000_0000
	if frame.Fin {
		header[0] = 0b1000_0000
	}

	header[0] |= frame.Opcode
	header[1] = byte(frame.Payloadlen)
	header[1] |= 0b0000_0000

	return header
}
