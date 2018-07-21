package ebpf

import (
	"github.com/newtools/ebpf/asm"

	"github.com/pkg/errors"
)

// Editor modifies eBPF instructions.
type Editor struct {
	instructions  *Instructions
	refs          map[string][]int
	offsets       map[*asm.Instruction]int
	encodedLength int
}

// Edit creates a new Editor.
//
// The editor retains a reference to insns and modifies its
// contents.
func Edit(insns *Instructions) *Editor {
	refs := make(map[string][]int)
	offsets := make(map[*asm.Instruction]int, len(*insns))
	encodedLength := 0
	for i, ins := range *insns {
		insPtr := &(*insns)[i]
		offsets[insPtr] = encodedLength
		encodedLength += ins.EncodedLength()

		if ins.Reference != "" {
			refs[ins.Reference] = append(refs[ins.Reference], i)
		}
	}
	return &Editor{insns, refs, offsets, encodedLength}
}

// ReferencedSymbols returns all referenced symbols.
//
// Each name appears only once, but the order is not guaranteed.
func (ed *Editor) ReferencedSymbols() []string {
	var out []string
	for ref := range ed.refs {
		out = append(out, ref)
	}
	return out
}

// RewriteMap rewrites a symbol to point at a Map.
func (ed *Editor) RewriteMap(symbol string, m *Map) error {
	indices := ed.refs[symbol]
	if len(indices) == 0 {
		return errors.Errorf("unknown symbol %v", symbol)
	}

	for _, index := range indices {
		load := &(*ed.instructions)[index]
		if load.OpCode != LdDW {
			return errors.Errorf("symbol %v: missing load instruction", symbol)
		}

		load.SrcRegister = 1
		load.Constant = int64(m.fd)
	}

	return nil
}

// RewriteUint64 rewrites a reference to a 64bit global variable to a constant.
//
// This is meant to be used with code emitted by LLVM, not hand written assembly.
func (ed *Editor) RewriteUint64(symbol string, value uint64) error {
	return ed.rewriteLoadAndDeref(symbol, LdXDW, 8, []int64{int64(value)})
}

// RewriteUint64Array rewrites a reference to a 64bit global array variable to a constant.
//
// This is meant to be used with code emitted by LLVM, not hand written assembly.
func (ed *Editor) RewriteUint64Array(symbol string, values []uint64) error {
	intValues := make([]int64, len(values))
	for i, v := range values {
		intValues[i] = int64(v)
	}

	return ed.rewriteLoadAndDeref(symbol, LdXDW, 8, intValues)
}

// RewriteUint32 rewrites all references to a 32bit global variable to a constant.
//
// This is meant to be used with code emitted by LLVM, not hand written assembly.
func (ed *Editor) RewriteUint32(symbol string, value uint32) error {
	return ed.rewriteLoadAndDeref(symbol, LdXW, 4, []int64{int64(value)})
}

// RewriteUint32Array rewrites all references to a 32bit global array variable to a constant.
//
// This is meant to be used with code emitted by LLVM, not hand written assembly.
func (ed *Editor) RewriteUint32Array(symbol string, values []uint32) error {
	intValues := make([]int64, len(values))
	for i, v := range values {
		intValues[i] = int64(v)
	}

	return ed.rewriteLoadAndDeref(symbol, LdXW, 4, intValues)
}

// RewriteUint16 rewrites all references to a 32bit global variable to a constant.
//
// This is meant to be used with code emitted by LLVM, not hand written assembly.
func (ed *Editor) RewriteUint16(symbol string, value uint16) error {
	return ed.rewriteLoadAndDeref(symbol, LdXH, 2, []int64{int64(value)})
}

// RewriteUint16Array rewrites all references to a 16bit global array variable to a constant.
//
// This is meant to be used with code emitted by LLVM, not hand written assembly.
func (ed *Editor) RewriteUint16Array(symbol string, values []uint16) error {
	intValues := make([]int64, len(values))
	for i, v := range values {
		intValues[i] = int64(v)
	}

	return ed.rewriteLoadAndDeref(symbol, LdXH, 2, intValues)
}

// RewriteUint8 rewrites all references to an 8bit global variable to a constant.
//
// This is meant to be used with code emitted by LLVM, not hand written assembly.
func (ed *Editor) RewriteUint8(symbol string, value uint8) error {
	return ed.rewriteLoadAndDeref(symbol, LdXB, 1, []int64{int64(value)})
}

// RewriteUint8Array rewrites all references to an 8bit global array variable to a constant.
//
// This is meant to be used with code emitted by LLVM, not hand written assembly.
func (ed *Editor) RewriteUint8Array(symbol string, values []uint8) error {
	intValues := make([]int64, len(values))
	for i, v := range values {
		intValues[i] = int64(v)
	}

	return ed.rewriteLoadAndDeref(symbol, LdXB, 1, intValues)
}

// RewriteBool rewrites all references to an boolean global variable to a constant.
//
// This is meant to be used with code emitted by LLVM, not hand written assembly.
func (ed *Editor) RewriteBool(symbol string, value bool) error {
	intValue := int64(0)
	if value {
		intValue = 1
	}
	return ed.rewriteLoadAndDeref(symbol, LdXB, 1, []int64{intValue})
}

// RewriteBoolArray rewrites all references to an boolean global array variable to a constant.
//
// This is meant to be used with code emitted by LLVM, not hand written assembly.
func (ed *Editor) RewriteBoolArray(symbol string, values []bool) error {
	intValues := make([]int64, len(values))
	for i, v := range values {
		intValues[i] = 0
		if v {
			intValues[i] = 1
		}
	}

	return ed.rewriteLoadAndDeref(symbol, LdXB, 1, intValues)
}

// rewriteLoadAndDeref deals with references to global variables as emitted by LLVM.
// When compiled they are represented by a dummy load instruction (which has a zero immediate)
// and a derefencing operation for the correct size.
func (ed *Editor) rewriteLoadAndDeref(symbol string, derefOp asm.OpCode, length int, values []int64) error {
	indices := ed.refs[symbol]
	if len(indices) == 0 {
		return errors.Errorf("unknown symbol %v", symbol)
	}
	for _, index := range indices {
		if index+1 >= len(*ed.instructions) {
			return errors.Errorf("symbol %v: expected at least two instructions")
		}

		load := &(*ed.instructions)[index]
		if load.OpCode != LdDW {
			return errors.Errorf("symbol %v: missing load instruction", symbol)
		}

		deref := &(*ed.instructions)[index+1]
		if deref.OpCode != derefOp {
			return errors.Errorf("symbol %v: incompatible value type", symbol, derefOp, deref.OpCode)
		}

		if int(deref.Offset)%length != 0 {
			return errors.Errorf("symbol %v: unaligned access")
		}

		index := int(deref.Offset) / length
		if index >= len(values) {
			return errors.Errorf("symbol %v: out of bounds dereference")
		}

		// Rewrite original load to new value
		load.Constant = values[index]

		// Replace the deref with a mov
		*deref = asm.Instruction{
			OpCode:      MovSrc,
			DstRegister: deref.DstRegister,
			SrcRegister: load.DstRegister,
		}
	}
	return nil
}

// Link resolves bpf-to-bpf calls.
//
// Each section may contain multiple functions / labels, and is only linked
// if the program being edited references one of these functions.
//
// Sections must not require linking themselves.
func (ed *Editor) Link(sections ...Instructions) error {
	// A map of symbols to the libraries which contain them.
	symbols := make(map[string]*linkEditor)
	for i, section := range sections {
		editor, err := newLinkEditor(section)
		if err != nil {
			return errors.Wrapf(err, "section %d", i)
		}
		for symbol := range editor.symbols {
			if symbols[symbol] != nil {
				return errors.Errorf("symbol %s is present in multiple sections")
			}
			symbols[symbol] = editor
		}
	}

	// Appending to ed.instructions would invalidate the pointers in
	// ed, so instead we append to a new slice and join them at the end.
	var linkedInsns Instructions

	// A list of already linked sections and the offset at which they were
	// linked, to avoid linking multiple times.
	linkedSections := make(map[*linkEditor]int)
	linkedLength := 0

	for symbol, indices := range ed.refs {
		for _, index := range indices {
			ins := &(*ed.instructions)[index]

			if ins.OpCode != Call || ins.SrcRegister != asm.R1 {
				continue
			}

			if ins.Constant != -1 {
				// This is already a valid call, do not rewrite it.
				continue
			}

			section := symbols[symbol]
			if section == nil {
				return errors.Errorf("symbol %s missing from libaries")
			}

			sectionOffset, ok := linkedSections[section]
			if !ok {
				sectionOffset = ed.encodedLength + linkedLength
				linkedLength += section.encodedLength
				linkedInsns = append(linkedInsns, *section.instructions...)
				linkedSections[section] = sectionOffset
			}

			insOffset := ed.offsets[ins]
			funcOffset := section.offsets[section.symbols[symbol]]

			// Calls are relative from the PC after the call instruction.
			// Calculate offset and adjust by one.
			ins.Constant = int64(sectionOffset + funcOffset - insOffset - 1)
		}
	}

	// ed.instructions has been fixed up. Append linked instructions and
	// recalculate ed.
	*ed.instructions = append(*ed.instructions, linkedInsns...)
	*ed = *Edit(ed.instructions)
	return nil
}

type linkEditor struct {
	*Editor
	symbols map[string]*asm.Instruction
}

func newLinkEditor(insns Instructions) (*linkEditor, error) {
	symbols := make(map[string]*asm.Instruction)

	for i, ins := range insns {
		insPtr := &insns[i]

		if ins.Symbol == "" {
			continue
		}

		if symbols[ins.Symbol] != nil {
			return nil, errors.Errorf("duplicate label %s", ins.Symbol)
		}

		symbols[ins.Symbol] = insPtr
	}

	return &linkEditor{
		Edit(&insns),
		symbols,
	}, nil
}
