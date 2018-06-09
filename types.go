package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"github.com/newtools/ebpf/asm"

	"github.com/pkg/errors"
)

//go:generate stringer -output types_string.go -type=MapType,ProgType

// MapType indicates the type map structure
// that will be initialized in the kernel.
type MapType uint32

// All the various map types that can be created
const (
	// Hash is a hash map
	Hash MapType = 1 + iota
	// Array is an array map
	Array
	// ProgramArray - A program array map is a special kind of array map whose map
	// values contain only file descriptors referring to other eBPF
	// programs.  Thus, both the key_size and value_size must be
	// exactly four bytes.  This map is used in conjunction with the
	// TailCall helper.
	ProgramArray
	// PerfEventArray - A perf event array is used in conjunction with PerfEventRead
	// and PerfEventOutput calls, to read the raw bpf_perf_data from the registers.
	PerfEventArray
	// PerCPUHash - This data structure is useful for people who have high performance
	// network needs and can reconcile adds at the end of some cycle, so that
	// hashes can be lock free without the use of XAdd, which can be costly.
	PerCPUHash
	// PerCPUArray - This data structure is useful for people who have high performance
	// network needs and can reconcile adds at the end of some cycle, so that
	// hashes can be lock free without the use of XAdd, which can be costly.
	// Each CPU gets a copy of this hash, the contents of all of which can be reconciled
	// later.
	PerCPUArray
	// StackTrace - This holds whole user and kernel stack traces, it can be retrieved with
	// GetStackID
	StackTrace
	// CGroupArray - This is a very niche structure used to help SKBInCGroup determine
	// if an skb is from a socket belonging to a specific cgroup
	CGroupArray
	// LRUHash - This allows you to create a small hash structure that will purge the
	// least recently used items rather than thow an error when you run out of memory
	LRUHash
	// LRUCPUHash - This is NOT like PerCPUHash, this structure is shared among the CPUs,
	// it has more to do with including the CPU id with the LRU calculation so that if a
	// particular CPU is using a value over-and-over again, then it will be saved, but if
	// a value is being retrieved a lot but sparsely across CPUs it is not as important, basically
	// giving weight to CPU locality over overall usage.
	LRUCPUHash
	// LPMTrie - This is an implementation of Longest-Prefix-Match Trie structure. It is useful,
	// for storing things like IP addresses which can be bit masked allowing for keys of differing
	// values to refer to the same reference based on their masks. See wikipedia for more details.
	LPMTrie
	// ArrayOfMaps - Each item in the array is another map. The inner map mustn't be a map of maps
	// itself.
	ArrayOfMaps
	// HashOfMaps - Each item in the hash map is another map. The inner map mustn't be a map of maps
	// itself.
	HashOfMaps
)

// hasPerCPUValue returns true if the Map stores a value per CPU.
func (mt MapType) hasPerCPUValue() bool {
	if mt == PerCPUHash || mt == PerCPUArray {
		return true
	}
	return false
}

const (
	_MapCreate = iota
	_MapLookupElem
	_MapUpdateElem
	_MapDeleteElem
	_MapGetNextKey
	_ProgLoad
	_ObjPin
	_ObjGet
	_ProgAttach
	_ProgDetach
	_ProgTestRun
	_ProgGetNextID
	_MapGetNextID
	_ProgGetFDByID
	_MapGetFDByID
	_ObjGetInfoByFD
)

const (
	_Any = iota
	_NoExist
	_Exist
)

// Limits and constants for the the eBPF runtime
const (
	// InstructionSize is the size of the BPF instructions
	InstructionSize = 8
)

// ALU64 instructions
// alu/alu64/jmp opcode structure:
// msb      lsb
// +----+-+---+
// |op  |s|cls|
// +----+-+---+
// If the s bit is zero, then the source operand is imm,
// If s is one, then the source operand is src.
// ALU Instructions 64 bit, eBPF only
const (
	// AddImm  add dst, imm   |  dst += imm
	AddImm = 0x07
	// AddSrc  add dst, src   |  dst += src
	AddSrc = 0x0f
	// SubImm  sub dst, imm   |  dst -= imm
	SubImm = 0x17
	// SubSrc  sub dst, src   |  dst -= src
	SubSrc = 0x1f
	// MulImm  mul dst, imm   |  dst *= imm
	MulImm = 0x27
	// MulSrc  mul dst, src   |  dst *= src
	MulSrc = 0x2f
	// DivImm  div dst, imm   |  dst /= imm
	DivImm = 0x37
	// DivSrc  div dst, src   |  dst /= src
	DivSrc = 0x3f
	// OrImm   or dst, imm    |  dst  |= imm
	OrImm = 0x47
	// OrSrc   or dst, src    |  dst  |= src
	OrSrc = 0x4f
	// AndImm  and dst, imm   |  dst &= imm
	AndImm = 0x57
	// AndSrc  and dst, src   |  dst &= src
	AndSrc = 0x5f
	// LShImm  lsh dst, imm   |  dst <<= imm
	LShImm = 0x67
	// LShSrc  lsh dst, src   |  dst <<= src
	LShSrc = 0x6f
	// RShImm  rsh dst, imm   |  dst >>= imm (logical)
	RShImm = 0x77
	// RShSrc  rsh dst, src   |  dst >>= src (logical)
	RShSrc = 0x7f
	// Neg     neg dst        |  dst = -dst
	Neg = 0x87
	// ModImm  mod dst, imm   |  dst %= imm
	ModImm = 0x97
	// ModSrc  mod dst, src   |  dst %= src
	ModSrc = 0x9f
	// XorImm  xor dst, imm   |  dst ^= imm
	XorImm = 0xa7
	// XorSrc  xor dst, src   |  dst ^= src
	XorSrc = 0xaf
	// MovImm  mov dst, imm   |  dst = imm
	MovImm = 0xb7
	// MovSrc  mov dst, src   |  dst = src
	MovSrc = 0xbf
	// ArShImm arsh dst, imm  |  dst >>= imm (arithmetic)
	ArShImm = 0xc7
	// ArShSrc arsh dst, src  |  dst >>= src (arithmetic)
	ArShSrc = 0xcf
)

// ALU Instructions 32 bit
// These instructions use only the lower 32 bits of their
// operands and zero the upper 32 bits of the destination register.
const (
	// Add32Imm add32 dst, imm  |  dst += imm
	Add32Imm = 0x04
	// Add32Src add32 dst, src  |  dst += src
	Add32Src = 0x0c
	// Sub32Imm sub32 dst, imm  |  dst -= imm
	Sub32Imm = 0x14
	// Sub32Src sub32 dst, src  |  dst -= src
	Sub32Src = 0x1c
	// Mul32Imm mul32 dst, imm  |  dst *= imm
	Mul32Imm = 0x24
	// Mul32Src mul32 dst, src  |  dst *= src
	Mul32Src = 0x2c
	// Div32Imm div32 dst, imm  |  dst /= imm
	Div32Imm = 0x34
	// Div32Src div32 dst, src  |  dst /= src
	Div32Src = 0x3c
	// Or32Imm  or32 dst, imm   |  dst |= imm
	Or32Imm = 0x44
	// Or32Src  or32 dst, src   |  dst |= src
	Or32Src = 0x4c
	// And32Imm and32 dst, imm  |  dst &= imm
	And32Imm = 0x54
	// And32Src and32 dst, src  |  dst &= src
	And32Src = 0x5c
	// LSh32Imm lsh32 dst, imm  |  dst <<= imm
	LSh32Imm = 0x64
	// LSh32Src lsh32 dst, src  |  dst <<= src
	LSh32Src = 0x6c
	// RSh32Imm rsh32 dst, imm  |  dst >>= imm (logical)
	RSh32Imm = 0x74
	// RSh32Src rsh32 dst, src  |  dst >>= src (logical)
	RSh32Src = 0x7c
	// Neg32    neg32 dst       |  dst = -dst
	Neg32 = 0x84
	// Mod32Imm mod32 dst, imm  |  dst %= imm
	Mod32Imm = 0x94
	// Mod32Src mod32 dst, src  |  dst %= src
	Mod32Src = 0x9c
	// Xor32Imm xor32 dst, imm  |  dst ^= imm
	Xor32Imm = 0xa4
	// Xor32Src xor32 dst, src  |  dst ^= src
	Xor32Src = 0xac
	// Mov32Imm mov32 dst, imm  |  dst eBPF only
	Mov32Imm = 0xb4
	// Mov32Src mov32 dst, src  |  dst eBPF only
	Mov32Src = 0xbc
)

// Byteswap Instructions
const (
	// LE16 le16 dst, imm == 16  |  dst = htole16(dst)
	LE16 = 0xd4
	// LE32 le32 dst, imm == 32  |  dst = htole32(dst)
	LE32 = 0xd4
	// LE64 le64 dst, imm == 64  |  dst = htole64(dst)
	LE64 = 0xd4
	// BE16 be16 dst, imm == 16  |  dst = htobe16(dst)
	BE16 = 0xdc
	// BE32 be32 dst, imm == 32  |  dst = htobe32(dst)
	BE32 = 0xdc
	// BE64 be64 dst, imm == 64  |  dst = htobe64(dst)
	BE64 = 0xdc
)

// Memory Instructions
const (
	// LdDW      lddw (src), dst, imm   |  dst = imm
	LdDW = 0x18
	// XAddStSrc xadd dst, src          |  *dst += src
	XAddStSrc = 0xdb
	// LdAbsB    ldabsb imm             |  r0 = (uint8_t *) (mem + imm)
	LdAbsB = 0x30
	// LdXW      ldxw dst, [src+off]    |  dst = *(uint32_t *) (src + off)
	LdXW = 0x61
	// LdXH      ldxh dst, [src+off]    |  dst = *(uint16_t *) (src + off)
	LdXH = 0x69
	// LdXB      ldxb dst, [src+off]    |  dst = *(uint8_t *) (src + off)
	LdXB = 0x71
	// LdXDW     ldxdw dst, [src+off]   |  dst = *(uint64_t *) (src + off)
	LdXDW = 0x79
	// StB       stb [dst+off], imm     |  *(uint8_t *) (dst + off) = imm
	StB = 0x72
	// StH       sth [dst+off], imm     |  *(uint16_t *) (dst + off) = imm
	StH = 0x6a
	// StW       stw [dst+off], imm     |  *(uint32_t *) (dst + off) = imm
	StW = 0x62
	// StDW      stdw [dst+off], imm    |  *(uint64_t *) (dst + off) = imm
	StDW = 0x7a
	// StXB      stxb [dst+off], src    |  *(uint8_t *) (dst + off) = src
	StXB = 0x73
	// StXH      stxh [dst+off], src    |  *(uint16_t *) (dst + off) = src
	StXH = 0x6b
	// StXW      stxw [dst+off], src    |  *(uint32_t *) (dst + off) = src
	StXW = 0x63
	// StXDW     stxdw [dst+off], src   |  *(uint64_t *) (dst + off) = src
	StXDW = 0x7b
	// LdAbsH  ldabsh imm             |  r0 = (uint16_t *) (imm)
	// Abs and Ind reference memory directly. This is always the context,
	// of whatever the eBPF program is. For example in a sock filter program
	// the memory context is the sk_buff struct.
	LdAbsH = 0x28
	// LdAbsW  ldabsw imm             |  r0 = (uint32_t *) (imm)
	LdAbsW = 0x20
	// LdAbsDW ldabsdw imm            |  r0 = (uint64_t *) (imm)
	LdAbsDW = 0x38
	// LdIndB  ldindb src, dst, imm   |  dst = (uint64_t *) (src + imm)
	LdIndB = 0x50
	// LdIndH  ldindh src, dst, imm   |  dst = (uint16_t *) (src + imm)
	LdIndH = 0x48
	// LdIndW  ldindw src, dst, imm   |  dst = (uint32_t *) (src + imm)
	LdIndW = 0x40
	// LdIndDW ldinddw src, dst, imm  |  dst = (uint64_t *) (src + imm)
	LdIndDW = 0x58
)

// Branch Instructions
const (
	// Ja      ja +off             |  PC += off
	Ja = 0x05
	// JEqImm  jeq dst, imm, +off  |  PC += off if dst == imm
	JEqImm = 0x15
	// JEqSrc  jeq dst, src, +off  |  PC += off if dst == src
	JEqSrc = 0x1d
	// JGTImm  jgt dst, imm, +off  |  PC += off if dst > imm
	JGTImm = 0x25
	// JGTSrc  jgt dst, src, +off  |  PC += off if dst > src
	JGTSrc = 0x2d
	// JGEImm  jge dst, imm, +off  |  PC += off if dst >= imm
	JGEImm = 0x35
	// JGESrc  jge dst, src, +off  |  PC += off if dst >= src
	JGESrc = 0x3d
	// JSETImm jset dst, imm, +off |  PC += off if dst & imm
	JSETImm = 0x45
	// JSETSrc jset dst, src, +off |  PC += off if dst & src
	JSETSrc = 0x4d
	// JNEImm  jne dst, imm, +off  |  PC += off if dst != imm
	JNEImm = 0x55
	// JNESrc  jne dst, src, +off  |  PC += off if dst != src
	JNESrc = 0x5d
	// JSGTImm jsgt dst, imm, +off |  PC += off if dst > imm (signed)
	JSGTImm = 0x65
	// JSGTSrc jsgt dst, src, +off |  PC += off if dst > src (signed)
	JSGTSrc = 0x6d
	// JSGEImm jsge dst, imm, +off |  PC += off if dst >= imm (signed)
	JSGEImm = 0x75
	// JSGESrc jsge dst, src, +off |  PC += off if dst >= src (signed)
	JSGESrc = 0x7d
	// Call    call imm            |  Function call
	Call = 0x85
	// Exit    exit                |  return r0
	Exit = 0x95
)

// All flags used by eBPF helper functions
const (
	// RecomputeCSUM SKBStoreBytes flags
	RecomputeCSUM = uint64(1)
	// FInvalidateHash SKBStoreBytes flags
	FInvalidateHash = uint64(1 << 1)

	// FHdrFieldMask CSUMReplaceL4 and CSUMReplaceL3 flags.
	// First 4 bits are for passing the header field size.
	FHdrFieldMask = uint64(0xF)

	// FPseudoHdr CSUMReplaceL4 flags
	FPseudoHdr = uint64(1 << 4)
	// FMarkMangled0 CSUMReplaceL4 flags
	FMarkMangled0 = uint64(1 << 5)
	// FMakrEnforce CSUMReplaceL4 flags
	FMakrEnforce = uint64(1 << 6)

	// FIngress CloneRedirect and Redirect flags
	FIngress = uint64(1)

	// FTunInfoIPV6 SKBSetTunnelKey and SKBGetTunnelKey flags
	FTunInfoIPV6 = uint(1)

	// FSkipFieldMask GetStackID flags
	FSkipFieldMask = uint64(0xff)
	// FUserStack GetStackID flags
	FUserStack = uint64(1 << 8)
	// FFastStackCMP GetStackID flags
	FFastStackCMP = uint64(1 << 9)
	// FReuseStackID GetStackID flags
	FReuseStackID = uint64(1 << 10)

	// FZeroCSUMTx SKBSetTunnelKey flag
	FZeroCSUMTX = uint64(1 << 1)
	// FZeroCSUMTx SKBSetTunnelKey flag
	FDontFragment = uint64(1 << 2)

	// FindIndexMask PerfEventOutput and PerfEventRead flags.
	FIndexMask = uint64(0xffffffff)
	// FCurrentCPU PerfEventOutput and PerfEventRead flags.
	FCurrentCPU = FIndexMask

	// FCtxLenMask PerfEventOutput for SKBuff input context.
	FCtxLenMask = uint64(0xfffff << 32)

	// AdjRoomNet Mode for SKBAdjustRoom helper.
	AdjRoomNet = 0
)

// ProgType of the eBPF program
type ProgType uint32

// eBPF program types
const (
	// Unrecognized program type
	Unrecognized ProgType = iota
	// SocketFilter socket or seccomp filter
	SocketFilter
	// Kprobe program
	Kprobe
	// SchedCLS traffic control shaper
	SchedCLS
	// SchedACT routing control shaper
	SchedACT
	// TracePoint program
	TracePoint
	// XDP program
	XDP
	// PerfEvent program
	PerfEvent
	// CGroupSKB program
	CGroupSKB
	// CGroupSock program
	CGroupSock
	// LWTIn program
	LWTIn
	// LWTOut program
	LWTOut
	// LWTXmit program
	LWTXmit
	// SockOps program
	SockOps
)

type bpfInstruction struct {
	OpCode    asm.OpCode
	Registers bpfRegisters
	Offset    int16
	Constant  int32
}

type bpfRegisters uint8

func newBPFRegisters(dst, src asm.Register) bpfRegisters {
	return bpfRegisters((src << 4) | (dst & 0xF))
}

func (r bpfRegisters) Dst() asm.Register {
	return asm.Register(r & 0xF)
}

func (r bpfRegisters) Src() asm.Register {
	return asm.Register(r >> 4)
}

// Instructions is the lowest level construct for a BPF snippet in array.
type Instructions []asm.Instruction

func (inss Instructions) String() string {
	return fmt.Sprint(inss)
}

// Format implements fmt.Formatter.
//
// The function only accepts 's' and 'v' formats, which are currently
// output identically. You can control indentation of symbols by
// specifying a width. Setting a precision controls the indentation of
// instructions.
// The default character is a tab, which can be overriden by specifying
// the ' ' space flag.
func (inss Instructions) Format(f fmt.State, c rune) {
	if c != 's' && c != 'v' {
		fmt.Fprintf(f, "{UNKNOWN FORMAT '%c'}", c)
		return
	}

	// Precision is better in this case, because it allows
	// specifying 0 padding easily.
	padding, ok := f.Precision()
	if !ok {
		padding = 1
	}

	indent := strings.Repeat("\t", padding)
	if f.Flag(' ') {
		indent = strings.Repeat(" ", padding)
	}

	symPadding, ok := f.Width()
	if !ok {
		symPadding = padding - 1
	}
	if symPadding < 0 {
		symPadding = 0
	}

	symIndent := strings.Repeat("\t", symPadding)
	if f.Flag(' ') {
		symIndent = strings.Repeat(" ", symPadding)
	}

	// Figure out how many digits we need to represent the highest
	// offset.
	highestOffset := 0
	for _, ins := range inss {
		highestOffset += ins.EncodedLength()
	}
	offsetWidth := int(math.Ceil(math.Log10(float64(highestOffset))))

	offset := 0
	for _, ins := range inss {
		if ins.Symbol != "" {
			fmt.Fprintf(f, "%s%s:\n", symIndent, ins.Symbol)
		}
		fmt.Fprintf(f, "%s%*d: %s\n", indent, offsetWidth, offset, ins)
		offset += ins.EncodedLength()
	}

	return
}

// MarshalBinary marshals a list of instructions into the format
// expected by the kernel.
func (inss Instructions) MarshalBinary() ([]byte, error) {
	wr := bytes.NewBuffer(make([]byte, 0, len(inss)*InstructionSize))
	for i, ins := range inss {
		if ins.OpCode == asm.InvalidOpCode {
			return nil, errors.Errorf("invalid operation at position %d", i)
		}

		// Encode least significant 32bit first for 64bit operations.
		cons := int32(ins.Constant)
		if ins.OpCode == LdDW {
			cons = int32(uint32(ins.Constant))
		}

		bpfi := bpfInstruction{
			ins.OpCode,
			newBPFRegisters(ins.DstRegister, ins.SrcRegister),
			ins.Offset,
			cons,
		}

		if err := binary.Write(wr, nativeEndian, &bpfi); err != nil {
			return nil, err
		}

		if ins.OpCode != LdDW {
			continue
		}

		bpfi = bpfInstruction{
			Constant: int32(ins.Constant >> 32),
		}

		if err := binary.Write(wr, nativeEndian, &bpfi); err != nil {
			return nil, err
		}
	}
	return wr.Bytes(), nil
}

// BPFIOp BPF instruction that stands alone (i.e. exit)
func BPFIOp(opCode asm.OpCode) asm.Instruction {
	return asm.Instruction{
		OpCode: opCode,
	}
}

// BPFIDst BPF instruction with a dst
func BPFIDst(opCode asm.OpCode, dst asm.Register) asm.Instruction {
	return asm.Instruction{
		OpCode:      opCode,
		DstRegister: dst,
	}
}

// BPFIImm BPF asm.Instruction with a constant
func BPFIImm(opCode asm.OpCode, imm int32) asm.Instruction {
	return asm.Instruction{
		OpCode:   opCode,
		Constant: int64(imm),
	}
}

// BPFIDstOff BPF instruction with a dst, and offset
func BPFIDstOff(opCode asm.OpCode, dst asm.Register, off int16) asm.Instruction {
	return asm.Instruction{
		OpCode: opCode,
		Offset: off,
	}
}

// BPFIDstImm BPF instruction with a dst, and constant
func BPFIDstImm(opCode asm.OpCode, dst asm.Register, imm int32) asm.Instruction {
	return asm.Instruction{
		OpCode:      opCode,
		DstRegister: dst,
		Constant:    int64(imm),
	}
}

// BPFIDstSrc BPF instruction with a dst, and src
func BPFIDstSrc(opCode asm.OpCode, dst, src asm.Register) asm.Instruction {
	return asm.Instruction{
		OpCode:      opCode,
		DstRegister: dst,
		SrcRegister: src,
	}
}

// BPFIDstOffImm BPF instruction with a dst, offset, and constant
func BPFIDstOffImm(opCode asm.OpCode, dst asm.Register, off int16, imm int32) asm.Instruction {
	return asm.Instruction{
		OpCode:      opCode,
		DstRegister: dst,
		Offset:      off,
		Constant:    int64(imm),
	}
}

// BPFIDstOffSrc BPF instruction with a dst, offset, and src.
func BPFIDstOffSrc(opCode asm.OpCode, dst, src asm.Register, off int16) asm.Instruction {
	return asm.Instruction{
		OpCode:      opCode,
		DstRegister: dst,
		SrcRegister: src,
		Offset:      off,
	}
}

// BPFIDstSrcImm BPF instruction with a dst, src, and constant
func BPFIDstSrcImm(opCode asm.OpCode, dst, src asm.Register, imm int32) asm.Instruction {
	return asm.Instruction{
		OpCode:      opCode,
		DstRegister: dst,
		SrcRegister: src,
		Constant:    int64(imm),
	}
}

// BPFIDstOffImmSrc BPF instruction with a dst, src, offset, and constant
func BPFIDstOffImmSrc(opCode asm.OpCode, dst, src asm.Register, off int16, imm int32) asm.Instruction {
	return asm.Instruction{
		OpCode:      opCode,
		DstRegister: dst,
		SrcRegister: src,
		Offset:      off,
		Constant:    int64(imm),
	}
}

// BPFILdMapFd loads a user space fd into a BPF program as a reference to a
// specific eBPF map.
func BPFILdMapFd(dst asm.Register, imm int) asm.Instruction {
	return BPFILdImm64Raw(dst, 1, int64(imm))
}

func BPFILdImm64(dst asm.Register, imm int64) asm.Instruction {
	return BPFILdImm64Raw(dst, 0, imm)
}

func BPFILdImm64Raw(dst, src asm.Register, imm int64) asm.Instruction {
	return asm.Instruction{
		OpCode:      LdDW,
		DstRegister: dst,
		SrcRegister: src,
		Constant:    imm,
	}
}

func BPFCall(fn asm.Func) asm.Instruction {
	return asm.Instruction{
		OpCode:   Call,
		Constant: int64(fn),
	}
}
