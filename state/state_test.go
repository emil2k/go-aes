package state

import (
	"bytes"
	"testing"
)

func TestStateSub(t *testing.T) {
	s := State([]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c})
	out := State([]byte{0xf1, 0xf3, 0x59, 0x47, 0x34, 0xe4, 0xb5, 0x24, 0x62, 0x68, 0x59, 0xc4, 0x01, 0x8a, 0x84, 0xeb})
	if s.Sub(); !bytes.Equal(s, out) {
		t.Errorf("State substitution failed with %v", &s)
	}
}

func TestStateInvSub(t *testing.T) {
	s := State([]byte{0xf1, 0xf3, 0x59, 0x47, 0x34, 0xe4, 0xb5, 0x24, 0x62, 0x68, 0x59, 0xc4, 0x01, 0x8a, 0x84, 0xeb})
	out := State([]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c})
	if s.InvSub(); !bytes.Equal(s, out) {
		t.Errorf("State substitution failed with %v", &s)
	}
}

func TestStateShift(t *testing.T) {
	s := State([]byte{0xf1, 0xf3, 0x59, 0x47, 0x34, 0xe4, 0xb5, 0x24, 0x62, 0x68, 0x59, 0xc4, 0x01, 0x8a, 0x84, 0xeb})
	out := State([]byte{0xf1, 0xe4, 0x59, 0xeb, 0x34, 0x68, 0x84, 0x47, 0x62, 0x8a, 0x59, 0x24, 0x01, 0xf3, 0xb5, 0xc4})
	if s.Shift(); !bytes.Equal(s, out) {
		t.Errorf("State shift failed with %v expected %v", &s, &out)
	}
}

func TestStateInvShift(t *testing.T) {
	s := State([]byte{0xf1, 0xf3, 0x59, 0x47, 0x34, 0xe4, 0xb5, 0x24, 0x62, 0x68, 0x59, 0xc4, 0x01, 0x8a, 0x84, 0xeb})
	out := State([]byte{0xf1, 0xf3, 0x59, 0x47, 0x34, 0xe4, 0xb5, 0x24, 0x62, 0x68, 0x59, 0xc4, 0x01, 0x8a, 0x84, 0xeb})
	s.Shift()
	if s.InvShift(); !bytes.Equal(s, out) {
		t.Errorf("State inverse shift failed with %v expected %v", &s, &out)
	}
}

func TestStateMix(t *testing.T) {
	s := State([]byte{0x63, 0x53, 0xe0, 0x8c, 0x09, 0x60, 0xe1, 0x04, 0xcd, 0x70, 0xb7, 0x51, 0xba, 0xca, 0xd0, 0xe7})
	out := State([]byte{0x5f, 0x72, 0x64, 0x15, 0x57, 0xf5, 0xbc, 0x92, 0xf7, 0xbe, 0x3b, 0x29, 0x1d, 0xb9, 0xf9, 0x1a})
	if s.Mix(); !bytes.Equal(s, out) {
		t.Errorf("Mix columns failed with %v", &s)
	}
}

func TestStateInvMix(t *testing.T) {
	s := State([]byte{0x63, 0x53, 0xe0, 0x8c, 0x09, 0x60, 0xe1, 0x04, 0xcd, 0x70, 0xb7, 0x51, 0xba, 0xca, 0xd0, 0xe7})
	out := State([]byte{0x63, 0x53, 0xe0, 0x8c, 0x09, 0x60, 0xe1, 0x04, 0xcd, 0x70, 0xb7, 0x51, 0xba, 0xca, 0xd0, 0xe7})
	s.Mix()
	if s.InvMix(); !bytes.Equal(s, out) {
		t.Errorf("Mix inverse columns failed with %v", &s)
	}
}

func TestStateGetCol(t *testing.T) {
	s := State([]byte{0xf1, 0xf3, 0x59, 0x47, 0x34, 0xe4, 0xb5, 0x24, 0x62, 0x68, 0x59, 0xc4, 0x01, 0x8a, 0x84, 0xeb})
	col := []byte{0xf1, 0xf3, 0x59, 0x47}
	if out := s.GetCol(0); !bytes.Equal(col, out) {
		t.Errorf("Get column failed with %v", out)
	}
}

func TestStateSetCol(t *testing.T) {
	col := []byte{0xff, 0xff, 0xff, 0xff}
	s := State([]byte{0xf1, 0xf3, 0x59, 0x47, 0x34, 0xe4, 0xb5, 0x24, 0x62, 0x68, 0x59, 0xc4, 0x01, 0x8a, 0x84, 0xeb})
	out := State([]byte{0xff, 0xff, 0xff, 0xff, 0x34, 0xe4, 0xb5, 0x24, 0x62, 0x68, 0x59, 0xc4, 0x01, 0x8a, 0x84, 0xeb})
	if s.SetCol(0, &col); !bytes.Equal(s, out) {
		t.Errorf("Set column failed with %v", &s)
	}
}

func TestStateGetRow(t *testing.T) {
	s := State([]byte{0xf1, 0xf3, 0x59, 0x47, 0x34, 0xe4, 0xb5, 0x24, 0x62, 0x68, 0x59, 0xc4, 0x01, 0x8a, 0x84, 0xeb})
	row := []byte{0xf3, 0xe4, 0x68, 0x8a}
	if out := s.GetRow(1); !bytes.Equal(row, out) {
		t.Errorf("Get row failed with %v", out)
	}
}

func TestStateSetRow(t *testing.T) {
	row := []byte{0x00, 0x01, 0x02, 0x03}
	s := State([]byte{0xf1, 0xf3, 0x59, 0x47, 0x34, 0xe4, 0xb5, 0x24, 0x62, 0x68, 0x59, 0xc4, 0x01, 0x8a, 0x84, 0xeb})
	out := State([]byte{0xf1, 0x00, 0x59, 0x47, 0x34, 0x01, 0xb5, 0x24, 0x62, 0x02, 0x59, 0xc4, 0x01, 0x03, 0x84, 0xeb})
	if s.SetRow(1, &row); !bytes.Equal(s, out) {
		t.Errorf("Set row failed with %v expected %v", &s, &out)
	}
}
