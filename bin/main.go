/* SPDX-License-Identifier: MIT */

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	libbpf "github.com/aquasecurity/libbpfgo"
)

const U_GID = 1000
const U_UID = 1000

const BPF_PROGRAM = "build/bpf.o" // in build/
const BPF_MAP_RINGBUF_NAME = "ringbuf"

const BPF_STR_MAX_LENGTH = 128
const BPF_EXEC_MAX_ARGUMENTS = 32

func main() {

	log.SetFlags(log.Lshortfile | log.Ltime | log.Ldate)

	err := run()
	if err != nil {
		log.Printf("exit with err: %v", err)
		os.Exit(1)
	}
}

func run() error {

	uid := os.Getuid()
	if uid != 0 {
		return fmt.Errorf("failed program needs to be run as root, is run as UID: %v", uid)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("run: open")
	bpf, err := libbpf.NewModuleFromFile(BPF_PROGRAM)
	if err != nil {
		return fmt.Errorf("failed to read bpf object from file: %w", err)
	}

	log.Printf("run: load")
	err = bpf.BPFLoadObject()
	if err != nil {
		return fmt.Errorf("failed to load bpf: %w", err)
	}

	defer func() {
		log.Printf("run: close")
		bpf.Close()
	}()

	log.Printf("run: attach")
	err = bpf.AttachPrograms()
	if err != nil {
		return fmt.Errorf("failed to attach bpf: %w", err)
	}

	defer func() {
		log.Printf("run: detach")
		bpf.DetachPrograms()
	}()

	log.Printf("run: dropping root")

	err = syscall.Setgid(U_GID)
	if err != nil {
		return fmt.Errorf("failed to drop root: failed to Setgid: %w", err)
	}

	err = syscall.Setuid(U_UID)
	if err != nil {
		return fmt.Errorf("failed to drop root: failed to Setuid: %w", err)
	}

	log.Printf("run: dropped root, running as uid:%v gid:%v euid:%v egid:%v", os.Getuid(), os.Getgid(), os.Geteuid(), os.Getegid())

	var eventsChannel = make(chan []byte)

	rb, err := bpf.InitRingBuf(BPF_MAP_RINGBUF_NAME, eventsChannel)
	if err != nil {
		return fmt.Errorf("failed init ring buffer: %w", err)
	}

	rb.Poll(1) // ms
	defer func() {
		log.Printf("run: stop channel")
		rb.Stop()
	}()

	log.Printf("run: waiting on channels")
	for {
		select {
		case e := <-sigs:
			{
				log.Printf("caught signal %v, returning", e)
				return nil
			}
		case e := <-eventsChannel:
			{
				handleEvent(e)
			}
		}
	}
}

type BpfMessage struct {
	Type         int32
	Err          int32
	Tgid         int32 // userspace PID
	Ptgid        int32 // userspace PPID
	Filename     [BPF_STR_MAX_LENGTH]uint8
	Arguments    [BPF_EXEC_MAX_ARGUMENTS][BPF_STR_MAX_LENGTH]uint8
	LenArguments int32
}

func handleEvent(e []byte) {

	m := BpfMessage{}
	err := binary.Read(bytes.NewReader(e), binary.LittleEndian, &m)
	if err != nil {
		log.Printf("failed to decode: %v", err)
	}

	switch m.Type {
	case 1:
		{
			log.Printf("err:%v type:%v tgid:%v ptgid:%v filename:%v", m.Err, m.Type, m.Tgid, m.Ptgid, string(m.Filename[:]))
		}
	case 2:
		{

			arguments := ""
			for k, v := range m.Arguments {
				if k >= int(m.LenArguments) {
					break
				}
				str := string(v[:])
				arguments += "["
				arguments += str
				arguments += "]"
			}

			log.Printf("err:%v type:%v tgid:%v arguments:%v", m.Err, m.Type, m.Tgid, arguments)
		}
	default:
		{
			log.Printf("error: event of type %v not known", m.Type)
		}
	}
}
