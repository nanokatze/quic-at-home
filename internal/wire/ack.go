package wire

import (
	"errors"
	"time"
)

const maxRawAckDelay = MaxVarint / 1000

type Ack struct {
	// Delay is a time delta since the highest acknowledged packet was
	// received and until this ACK was sent.
	Delay time.Duration

	Ranges PacketNumberRanges
}

func IsAck(t byte) bool { return t == 0b00000010 }

func DecodeAck(r *Reader, limit int) (Ack, error) {
	r.ReadByte()

	max, err := DecodeVarint(r)
	if err != nil {
		return Ack{}, err
	}

	rawDelay, err := DecodeVarint(r)
	if err != nil {
		return Ack{}, err
	}
	delay := time.Duration(min(rawDelay, maxRawAckDelay)) * time.Microsecond

	min, err := decodeDiff(r, max)
	if err != nil {
		return Ack{}, err
	}

	n, err := DecodeVarint(r)
	if err != nil {
		return Ack{}, err
	}

	var ranges PacketNumberRanges
	for i := int64(0); ; i++ {
		if len(ranges) < limit {
			ranges = append(ranges, PacketNumberRange{PacketNumber(min), PacketNumber(max)})
		}
		if i >= n {
			break
		}
		max, err = decodeDiff(r, min-2)
		if err != nil {
			return Ack{}, err
		}
		min, err = decodeDiff(r, max)
		if err != nil {
			return Ack{}, err
		}
	}

	return Ack{
		Delay:  delay,
		Ranges: ranges,
	}, nil
}

func decodeDiff(r *Reader, max int64) (int64, error) {
	gap, err := DecodeVarint(r)
	if err != nil {
		return 0, err
	}
	if max < gap {
		return 0, errors.New("invalid range")
	}
	return max - gap, nil
}

func (a Ack) Encode(w *Writer) error {
	if err := w.WriteByte(0b00000010); err != nil {
		return err
	}
	if err := EncodeVarint(w, int64(a.Ranges[0].Max)); err != nil {
		return err
	}
	if err := EncodeVarint(w, int64(a.Delay.Microseconds())); err != nil {
		return err
	}
	if err := encodeDiff(w, int64(a.Ranges[0].Max), int64(a.Ranges[0].Min)); err != nil {
		return err
	}
	if err := EncodeVarint(w, int64(len(a.Ranges)-1)); err != nil {
		return err
	}
	prevMin := a.Ranges[0].Min
	for _, r := range a.Ranges[1:] {
		if err := encodeDiff(w, int64(prevMin), int64(r.Max)+2); err != nil {
			return err
		}
		if err := encodeDiff(w, int64(r.Max), int64(r.Min)); err != nil {
			return err
		}
		prevMin = r.Min
	}
	return nil
}

func encodeDiff(w *Writer, x, y int64) error { return EncodeVarint(w, x-y) }
