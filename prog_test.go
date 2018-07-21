package ebpf

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/newtools/ebpf/asm"
)

func TestProgramRun(t *testing.T) {
	pat := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	buf := make([]byte, 14)

	// r1  : ctx_start
	// r1+4: ctx_end
	ins := Instructions{
		// r2 = *(r1+4)
		BPFIDstOffSrc(LdXW, asm.R2, asm.R1, 4),
		// r1 = *(r1+0)
		BPFIDstOffSrc(LdXW, asm.R1, asm.R1, 0),
		// r3 = r1
		BPFIDstSrc(MovSrc, asm.R3, asm.R1),
		// r3 += len(buf)
		BPFIDstImm(AddImm, asm.R3, int32(len(buf))),
		// if r3 > r2 goto +len(pat)
		BPFIDstOffSrc(JGTSrc, asm.R3, asm.R2, int16(len(pat))),
	}
	for i, b := range pat {
		ins = append(ins, BPFIDstOffImm(StB, asm.R1, int16(i), int32(b)))
	}
	ins = append(ins,
		// return 42
		BPFILdImm64(asm.R0, 42),
		BPFIOp(Exit),
	)

	prog, err := NewProgram(&ProgramSpec{XDP, ins, "MIT", 0})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	ret, out, err := prog.Test(buf)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 42 {
		t.Error("Expected return value to be 42, got", ret)
	}

	if !bytes.Equal(out[:len(pat)], pat) {
		t.Errorf("Expected %v, got %v", pat, out)
	}
}

func TestProgramPin(t *testing.T) {
	prog, err := NewProgram(&ProgramSpec{
		Type: XDP,
		Instructions: Instructions{
			BPFILdImm64(asm.R0, 0),
			BPFIOp(Exit),
		},
		License: "MIT",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	tmp, err := ioutil.TempDir("/sys/fs/bpf", "ebpf-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	path := filepath.Join(tmp, "program")
	if err := prog.Pin(path); err != nil {
		t.Fatal(err)
	}
	prog.Close()

	prog, err = LoadPinnedProgram(path)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	if prog.progType != XDP {
		t.Error("Expected pinned program to have type XDP, but got", prog.progType)
	}
}

func TestProgramVerifierOutput(t *testing.T) {
	_, err := NewProgram(&ProgramSpec{
		Type: XDP,
		Instructions: Instructions{
			BPFIOp(Exit),
		},
		License: "MIT",
	})
	if err == nil {
		t.Fatal("Expected program to be invalid")
	}

	if strings.Index(err.Error(), "exit") == -1 {
		t.Error("No verifier output in error message")
	}
}
