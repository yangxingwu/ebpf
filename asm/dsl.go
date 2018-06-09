package asm

// Exit emits an exit instruction.
//
// Requires a return value in R0.
func Exit() Instruction {
	return Instruction{
		OpCode: OpCode(JmpClass).SetJumpOp(ExitOp),
	}
}

// Load emits `dst = *(size *)(src + offset)`.
func Load(dst Register, src Register, offset int16, size Size) Instruction {
	return Instruction{
		OpCode:      OpCode(LdXClass).SetMode(MemMode).SetSize(size),
		DstRegister: dst,
		SrcRegister: src,
		Offset:      offset,
	}
}

// LoadImm emits `dst = (size)value`.
func LoadImm(dst Register, value int64, size Size) Instruction {
	return Instruction{
		OpCode:   OpCode(LdClass).SetMode(ImmMode).SetSize(size),
		Constant: value,
	}
}

// LoadAbs emits `r0 = ntoh(*(size *)(((sk_buff *)R6)->data + offset))`.
func LoadAbs(offset int32, size Size) Instruction {
	return Instruction{
		OpCode:   OpCode(LdClass).SetMode(AbsMode).SetSize(size),
		Constant: int64(offset),
	}
}

// LoadInd emits `dst = ntoh(*(size *)(((sk_buff *)R6)->data + src + offset))`.
func LoadInd(dst, src Register, offset int32, size Size) Instruction {
	return Instruction{
		OpCode:      OpCode(LdClass).SetMode(IndMode).SetSize(size),
		DstRegister: dst,
		SrcRegister: src,
		Constant:    int64(offset),
	}
}

// Store emits `*(size *)(dst + offset) = src`
func Store(dst Register, offset int16, src Register, size Size) Instruction {
	return Instruction{
		OpCode:      OpCode(StXClass).SetMode(MemMode).SetSize(size),
		DstRegister: dst,
		SrcRegister: src,
		Offset:      offset,
	}
}

// StoreImm emits `*(size *)(dst + offset) = value`.
func StoreImm(dst Register, offset int16, value int64, size Size) Instruction {
	return Instruction{
		OpCode:      OpCode(StClass).SetMode(MemMode).SetSize(size),
		DstRegister: dst,
		Offset:      offset,
		Constant:    value,
	}
}
