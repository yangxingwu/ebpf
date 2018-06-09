package asm

import (
	"fmt"
	"io"
	"strings"
)

//go:generate stringer -output opcode_string.go -type=Class,Size,Mode,Source,Endianness,ALUOp,JumpOp

type encoding int

const (
	unknownEncoding encoding = iota
	loadOrStore
	jumpOrALU
)

// Class of operations
//
//    msb      lsb
//    +---+--+---+
//    |mde|sz|CLS|
//    +---+--+---+
type Class uint8

const classMask OpCode = 0x07

const (
	// LdClass load memory
	LdClass Class = 0x00
	// LdXClass load memory from constant
	LdXClass Class = 0x01
	// StClass load registry from memory
	StClass Class = 0x02
	// StXClass load registry from constan
	StXClass Class = 0x03
	// ALUClass arithmetic operators
	ALUClass Class = 0x04
	// JmpClass jump operators
	JmpClass Class = 0x05
	// ALU64Class arithmetic in 64 bit mode
	ALU64Class Class = 0x07
)

func (cls Class) encoding() encoding {
	switch cls {
	case LdClass, LdXClass, StClass, StXClass:
		return loadOrStore
	case ALU64Class, ALUClass, JmpClass:
		return jumpOrALU
	default:
		return unknownEncoding
	}
}

// Size load and store operations
//
//    msb      lsb
//    +---+--+---+
//    |mde|SZ|cls|
//    +---+--+---+
type Size uint8

const sizeMask OpCode = 0x18

const (
	// InvalidSize is returned by getters when invoked
	// on non load / store OpCodes
	InvalidSize Size = 0xff
	// DWord - double word; 64 bits
	DWord Size = 0x18
	// Word - word; 32 bits
	Word Size = 0x00
	// Half - half-word; 16 bits
	Half Size = 0x08
	// Byte - byte; 8 bits
	Byte Size = 0x10
)

// Mode for load and store operations
//
//    msb      lsb
//    +---+--+---+
//    |MDE|sz|cls|
//    +---+--+---+
type Mode uint8

const modeMask OpCode = 0xe0

const (
	// InvalidMode is returned by getters when invoked
	// on non load / store OpCodes
	InvalidMode Mode = 0xff
	// ImmMode - immediate value
	ImmMode Mode = 0x00
	// AbsMode - immediate value + offset
	AbsMode Mode = 0x20
	// IndMode - indirect (imm+src)
	IndMode Mode = 0x40
	// MemMode - load from memory
	MemMode Mode = 0x60
	// XAddMode - add atomically across processors.
	XAddMode Mode = 0xc0
)

// Source of ALU / ALU64 / Branch operations
//
//    msb      lsb
//    +----+-+---+
//    |op  |S|cls|
//    +----+-+---+
type Source uint8

const sourceMask OpCode = 0x08

// Source bitmask
const (
	// InvalidSource is returned by getters when invoked
	// on non ALU / branch OpCodes.
	InvalidSource Source = 0xff
	// ImmSource src is from constant
	ImmSource Source = 0x00
	// RegSource src is from register
	RegSource Source = 0x08
)

// The Endianness of a byte swap instruction.
type Endianness uint8

const endianMask = sourceMask

// Endian flags
const (
	InvalidEndian Endianness = 0xff
	// Convert from / to little endian
	LittleEndian Endianness = 0x00
	// Convert from / to big endian
	BigEndian Endianness = 0x08
)

// ALUOp are ALU / ALU64 operations
//
//    msb      lsb
//    +----+-+---+
//    |OP  |s|cls|
//    +----+-+---+
type ALUOp uint8

const aluMask OpCode = 0xf0

const (
	// InvalidALUOp is returned by getters when invoked
	// on non ALU OpCodes
	InvalidALUOp ALUOp = 0xff
	// Add - addition
	Add ALUOp = 0x00
	// Sub - subtraction
	Sub ALUOp = 0x10
	// Mul - multiplication
	Mul ALUOp = 0x20
	// Div - division
	Div ALUOp = 0x30
	// Or - bitwise or
	Or ALUOp = 0x40
	// And - bitwise and
	And ALUOp = 0x50
	// LSh - bitwise shift left
	LSh ALUOp = 0x60
	// RSh - bitwise shift right
	RSh ALUOp = 0x70
	// Neg - sign/unsign signing bit
	Neg ALUOp = 0x80
	// Mod - modulo
	Mod ALUOp = 0x90
	// XOr - bitwise xor
	XOr ALUOp = 0xa0
	// Mov - move value from one place to another
	Mov ALUOp = 0xb0
	// ArSh - arithmatic shift
	ArSh ALUOp = 0xc0
	// Endian - endian conversions
	Endian ALUOp = 0xd0
)

// Reg emits `dst (op) src`.
func (op ALUOp) Reg(dst, src Register) Instruction {
	return Instruction{
		OpCode:      OpCode(ALU64Class).SetALUOp(op).SetSource(RegSource),
		DstRegister: dst,
		SrcRegister: src,
	}
}

// Imm emits `dst (op) value`.
func (op ALUOp) Imm(dst Register, value int64) Instruction {
	return Instruction{
		OpCode:      OpCode(ALU64Class).SetALUOp(op).SetSource(ImmSource),
		DstRegister: dst,
		Constant:    int64(value),
	}
}

// Reg32 emits `dst (op) src`, zeroing the upper 32 bit of dst.
func (op ALUOp) Reg32(dst, src Register) Instruction {
	return Instruction{
		OpCode:      OpCode(ALUClass).SetALUOp(op).SetSource(RegSource),
		DstRegister: dst,
		SrcRegister: src,
	}
}

// Imm32 emits `dst (op) value`, zeroing the upper 32 bit of dst.
func (op ALUOp) Imm32(dst Register, value int64) Instruction {
	return Instruction{
		OpCode:      OpCode(ALUClass).SetALUOp(op).SetSource(ImmSource),
		DstRegister: dst,
		Constant:    int64(value),
	}
}

// JumpOp affect control flow.
//
//    msb      lsb
//    +----+-+---+
//    |OP  |s|cls|
//    +----+-+---+
type JumpOp uint8

const jumpMask OpCode = aluMask

const (
	// InvalidJumpOp is returned by getters when invoked
	// on non branch OpCodes
	InvalidJumpOp JumpOp = 0xff
	// Ja jumps to address unconditionally
	Ja JumpOp = 0x00
	// JEq jumps to address if r == imm
	JEq JumpOp = 0x10
	// JGT jumps to address if r > imm
	JGT JumpOp = 0x20
	// JGEq jumps to address if r >= imm
	JGEq JumpOp = 0x30
	// JSEq jumps to address if signed r == signed imm
	JSEq JumpOp = 0x40
	// JNEq jumps to address if r != imm, eBPF only
	JNEq JumpOp = 0x50
	// JSGT jumps to address if signed r > signed imm, eBPF only
	JSGT JumpOp = 0x60
	// JSGEq jumps to address if signed r >= signed imm, eBPF only
	JSGEq JumpOp = 0x70
	// Call builtin or user defined function from imm, eBPF only
	Call JumpOp = 0x80
	// ExitOp ends execution, with value in r0
	ExitOp JumpOp = 0x90
)

// Imm compares dst to value, and adjusts PC by offset if the condition is fulfilled.
func (op JumpOp) Imm(dst Register, value int64, offset int16) Instruction {
	if op == Call || op == ExitOp {
		// TODO Return invalid Instruction
	}

	return Instruction{
		OpCode:      OpCode(JmpClass).SetJumpOp(op).SetSource(ImmSource),
		DstRegister: dst,
		Offset:      offset,
		Constant:    value,
	}
}

// Reg compares dst to src, and adjusts PC by offset if the condition is fulfilled.
func (op JumpOp) Reg(dst, src Register, offset int16) Instruction {
	return Instruction{
		OpCode:      OpCode(JmpClass).SetJumpOp(op).SetSource(RegSource),
		DstRegister: dst,
		SrcRegister: src,
		Offset:      offset,
	}
}

// OpCode is a packed eBPF opcode.
//
// Its encoding is defined by a Class value:
//
//    msb      lsb
//    +----+-+---+
//    | ???? |CLS|
//    +----+-+---+
type OpCode uint8

// InvalidOpCode is returned by setters on OpCode
const InvalidOpCode OpCode = 0xff

// Class returns the class of operation.
func (op OpCode) Class() Class {
	return Class(op & classMask)
}

// Mode returns the mode for load and store operations.
func (op OpCode) Mode() Mode {
	if op.Class().encoding() != loadOrStore {
		return InvalidMode
	}
	return Mode(op & modeMask)
}

// Size returns the size for load and store operations.
func (op OpCode) Size() Size {
	if op.Class().encoding() != loadOrStore {
		return InvalidSize
	}
	return Size(op & sizeMask)
}

// Source returns the source for branch and ALU operations.
func (op OpCode) Source() Source {
	if op.Class().encoding() != jumpOrALU {
		return InvalidSource
	}
	return Source(op & sourceMask)
}

// ALUOp returns the ALUOp.
func (op OpCode) ALUOp() ALUOp {
	if op.Class().encoding() != jumpOrALU {
		return InvalidALUOp
	}
	return ALUOp(op & aluMask)
}

// Endianness returns the Endianness for a byte swap instruction.
func (op OpCode) Endianness() Endianness {
	if op != OpCode(ALUClass).SetALUOp(Endian) && op != OpCode(ALU64Class).SetALUOp(Endian) {
		return InvalidEndian
	}
	return Endianness(op & endianMask)
}

// JumpOp returns the JumpOp.
func (op OpCode) JumpOp() JumpOp {
	if op.Class().encoding() != jumpOrALU {
		return InvalidJumpOp
	}
	return JumpOp(op & jumpMask)
}

func (op OpCode) SetMode(mode Mode) OpCode {
	if op.Class().encoding() != loadOrStore || !valid(OpCode(mode), modeMask) {
		return InvalidOpCode
	}
	return (op & ^modeMask) | OpCode(mode)
}

func (op OpCode) SetSize(size Size) OpCode {
	if op.Class().encoding() != loadOrStore || !valid(OpCode(size), sizeMask) {
		return InvalidOpCode
	}
	return (op & ^sizeMask) | OpCode(size)
}

func (op OpCode) SetSource(source Source) OpCode {
	if op.Class().encoding() != jumpOrALU || !valid(OpCode(source), sourceMask) {
		return InvalidOpCode
	}
	return (op & ^sourceMask) | OpCode(source)
}

func (op OpCode) SetALUOp(alu ALUOp) OpCode {
	if op.Class().encoding() != jumpOrALU || !valid(OpCode(alu), aluMask) {
		return InvalidOpCode
	}
	return (op & ^aluMask) | OpCode(alu)
}

func (op OpCode) SetJumpOp(jump JumpOp) OpCode {
	if op.Class().encoding() != jumpOrALU || !valid(OpCode(jump), jumpMask) {
		return InvalidOpCode
	}
	return (op & ^jumpMask) | OpCode(jump)
}

func (op OpCode) Format(f fmt.State, c rune) {
	if c != 'v' {
		fmt.Fprintf(f, "{UNRECOGNIZED: %c}", c)
		return
	}

	class := op.Class()
	io.WriteString(f, strings.TrimSuffix(class.String(), "Class"))

	switch class {
	case LdClass, LdXClass, StClass, StXClass:
		mode := op.Mode()
		modeStr := strings.TrimSuffix(mode.String(), "Mode")
		if mode == MemMode {
			modeStr = ""
		}
		io.WriteString(f, modeStr)

		switch op.Size() {
		case DWord:
			io.WriteString(f, "DW")
		case Word:
			io.WriteString(f, "W")
		case Half:
			io.WriteString(f, "H")
		case Byte:
			io.WriteString(f, "B")
		}

	case ALU64Class, ALUClass:
		if op.ALUOp() == Endian {
			io.WriteString(f, op.Endianness().String())
			return
		}

		io.WriteString(f, op.ALUOp().String())

		// Width for Endian is controlled by Constant
		if class == ALUClass && op.ALUOp() != Endian {
			io.WriteString(f, "32")
		}

		io.WriteString(f, strings.TrimSuffix(op.Source().String(), "Source"))

	case JmpClass:
		io.WriteString(f, strings.TrimSuffix(op.JumpOp().String(), "Op"))
		if jop := op.JumpOp(); jop != ExitOp && jop != CallOp {
			io.WriteString(f, strings.TrimSuffix(op.Source().String(), "Source"))
		}

	default:
		fmt.Fprintf(f, "%#x", op)
	}
}

// valid returns true if all bits in value are covered by mask.
func valid(value, mask OpCode) bool {
	return value & ^mask == 0
}
