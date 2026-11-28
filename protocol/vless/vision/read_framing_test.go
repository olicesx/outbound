package vision

import (
	"bytes"
	"io"
	"testing"
)

func TestReadPreservesFramingAcrossPaddingAndHandoff(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command byte
		want    string
	}{
		{"end", commandPaddingEnd, "framedoverlay"},
		{"direct", commandPaddingDirect, "framedtlsbufferrawbufferunderlay"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := bytes.Repeat([]byte{1}, 16)
			var wire bytes.Buffer
			wire.Write(id)
			wire.Write([]byte{commandPaddingContinue, 0, 0, 0, 2, 7, 8})
			wire.Write([]byte{tc.command, 0, 6, 0, 1})
			wire.WriteString("framed")
			wire.WriteByte(9)
			wire.WriteString("overlay")
			vc := &Conn{Conn: &memConn{reader: bytes.NewReader([]byte("underlay"))}, overlayConn: &memConn{reader: bytes.NewReader(wire.Bytes())}, userUUID: id, readFilterUUID: true}
			vc.reader = &readWrapper{vision: vc}
			if tc.command == commandPaddingDirect {
				vc.input = bytes.NewReader([]byte("tlsbuffer"))
				vc.rawInput = bytes.NewBufferString("rawbuffer")
			}
			var got bytes.Buffer
			b := make([]byte, 3)
			for {
				n, err := vc.Read(b)
				got.Write(b[:n])
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if got.String() != tc.want {
				t.Fatalf("Read delivered %q, want %q", got.String(), tc.want)
			}
		})
	}
}
