// +build linux

package ebpf_test

import (
	"flag"
	"fmt"
	"syscall"
	"time"

	"github.com/newtools/ebpf"
	"github.com/newtools/zsocket/nettypes"
)

// ExampleSocketELFFile demonstrates how to load an ELF
// program from a file and attach it to a socket.
func Example_socketELFFile() {
	const SO_ATTACH_BPF = 50

	fileName := flag.String("file", "", "path to sockex1")
	index := flag.Int("index", 0, "specify ethernet index")
	flag.Parse()
	coll, err := ebpf.LoadCollection(*fileName)
	if err != nil {
		panic(err)
	}
	sock, err := openRawSock(*index)
	if err != nil {
		panic(err)
	}
	prog, ok := coll.Programs["bpf_prog1"]
	if !ok {
		panic(fmt.Errorf("no program named \"bpf_prog1\" found"))
	}
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD()); err != nil {
		panic(err)
	}
	fmt.Printf("Filtering on eth index: %d\n", *index)
	fmt.Println("Packet stats:")
	bpfMap, ok := coll.Maps["my_map"]
	if !ok {
		panic(fmt.Errorf("no map named \"my_map\" found"))
	}
	for {
		time.Sleep(time.Second)
		var icmp uint64
		var tcp uint64
		var udp uint64
		ok, err := bpfMap.Get(uint32(nettypes.ICMP), &icmp)
		if err != nil {
			panic(err)
		}
		assertTrue(ok, "icmp key not found")
		ok, err = bpfMap.Get(uint32(nettypes.TCP), &tcp)
		if err != nil {
			panic(err)
		}
		assertTrue(ok, "tcp key not found")
		ok, err = bpfMap.Get(uint32(nettypes.UDP), &udp)
		if err != nil {
			panic(err)
		}
		assertTrue(ok, "udp key not found")
		fmt.Printf("\r\033[m\tICMP: %d TCP: %d UDP: %d", icmp, tcp, udp)
	}
}
