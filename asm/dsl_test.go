package asm

import (
	"testing"
)

func TestDSL(t *testing.T) {
	testcases := []struct {
		name string
		have Instruction
		want Instruction
	}{
		{"Call", Call(MapLookupElement), Instruction{OpCode: 0x85, Constant: 1}},
		{"Exit", Exit(), Instruction{OpCode: 0x95}},
		{"LoadAbs", LoadAbs(2, Byte), Instruction{OpCode: 0x30, Constant: 2}},
		{"Store", Store(RFP, -4, R0, Word), Instruction{
			OpCode:      0x63,
			DstRegister: RFP,
			SrcRegister: R0,
			Offset:      -4,
		}},
		{"OpImm(Add)", OpImm(Add, R1, 22), Instruction{OpCode: 0x07, DstRegister: R1, Constant: 22}},
		{"Op(Add)", Op(Add, R1, R2), Instruction{OpCode: 0x0f, DstRegister: R1, SrcRegister: R2}},
		{"Op32Imm(Add)", Op32Imm(Add, R1, 22), Instruction{
			OpCode: 0x04, DstRegister: R1, Constant: 22,
		}},
	}

	for _, tc := range testcases {
		if tc.have != tc.want {
			t.Errorf("%s: have %v, want %v", tc.name, tc.have, tc.want)
		}
	}
}
