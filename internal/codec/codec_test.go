package codec

import "testing"

func TestRoundTrip(t *testing.T) {
	in := []byte{0, 1, 2, 255, 10, 32}
	s := Encode(in)
	out, err := Decode(s)
	if err != nil || string(out) != string(in) {
		t.Fatalf("%q %v %q", s, err, out)
	}
	if _, err := Decode(s + "\n"); err == nil {
		t.Fatal("accepted newline")
	}
	if _, err := DecodeFixed(s, len(in)+1); err == nil {
		t.Fatal("wrong length")
	}
	if _, err := Decode("@@@"); err == nil {
		t.Fatal("accepted garbage")
	}
}
