package asm

import (
	"fmt"
	"io"
)

// Instruction is a single eBPF instruction.
type Instruction struct {
	OpCode      OpCode
	DstRegister Register
	SrcRegister Register
	Offset      int16
	Constant    int64
	Reference   string
	Symbol      string
}

// Ref creates a reference to a symbol.
func (ins Instruction) Ref(symbol string) Instruction {
	ins.Reference = symbol
	return ins
}

// Sym creates a symbol.
func (ins Instruction) Sym(name string) Instruction {
	ins.Symbol = name
	return ins
}

// EncodedLength returns the encoded length in number of instructions.
func (ins Instruction) EncodedLength() int {
	if ins.OpCode.Size() == DWord {
		return 2
	}
	return 1
}

var classMap = map[Class]string{
	LdClass:    "Ld",
	LdXClass:   "LdX",
	StClass:    "St",
	StXClass:   "StX",
	ALUClass:   "ALU32",
	JmpClass:   "Jmp",
	ALU64Class: "ALU64",
}

// Format implements fmt.Formatter.
func (ins Instruction) Format(f fmt.State, c rune) {
	if c != 'v' {
		fmt.Fprintf(f, "{UNRECOGNIZED: %c}", c)
		return
	}

	op := ins.OpCode
	switch cls := op.Class(); cls {
	case LdClass, LdXClass, StClass, StXClass:
		switch op.Mode() {
		case ImmMode:
			fmt.Fprintf(f, "%v dst: %s imm: %d", op, ins.DstRegister, ins.Constant)
		case AbsMode:
			fmt.Fprintf(f, "%v imm: %d", op, ins.Constant)
		case IndMode:
			fmt.Fprintf(f, "%v dst: %s src: %s imm: %d", op, ins.DstRegister, ins.SrcRegister, ins.Constant)
		case MemMode:
			fmt.Fprintf(f, "%v dst: %s src: %s off: %d imm: %d", op, ins.DstRegister, ins.SrcRegister, ins.Offset, ins.Constant)
		case XAddMode:
			fmt.Fprintf(f, "%v dst: %s src: %s", op, ins.DstRegister, ins.SrcRegister)
		}

	case ALU64Class, ALUClass:
		// dst src imm off
		fmt.Fprintf(f, "%v dst: %s", op, ins.DstRegister)
		if op.ALUOp() == Endian || op.Source() == ImmSource {
			fmt.Fprintf(f, " imm: %d", ins.Constant)
		} else {
			fmt.Fprintf(f, " src: %s", ins.SrcRegister)
		}

	case JmpClass:
		switch jop := op.JumpOp(); jop {
		case ExitOp:
			io.WriteString(f, "Exit")
			return

		case CallOp:
			if ins.SrcRegister == R1 {
				// bpf-to-bpf call
				fmt.Fprintf(f, "Call %v", ins.Constant)
			} else {
				fmt.Fprintf(f, "Call %v", Func(ins.Constant))
			}

		default:
			if op.Source() == ImmSource {
				fmt.Fprintf(f, "%vImm dst: %s off: %d imm: %d", op, ins.DstRegister, ins.Offset, ins.Constant)
			} else {
				fmt.Fprintf(f, "%vSrc dst: %s off: %d src: %s", op, ins.DstRegister, ins.Offset, ins.SrcRegister)
			}
		}
	}
}
