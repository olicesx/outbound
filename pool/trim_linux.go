//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package pool

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// DefaultTrimThreshold is the consecutive idle rounds required before reclaiming physical pages.
const DefaultTrimThreshold = 3

// ReleasePhysicalPages aligns the byte slice to operating system page boundaries
// and advises the kernel with MADV_DONTNEED. The underlying physical frames are immediately
// surrendered back to the operating system, reducing the resident set size (RSS),
// while preserving the virtual address range.
func ReleasePhysicalPages(b []byte) (int, bool) {
	if len(b) == 0 {
		return 0, false
	}
	pageSize := uintptr(os.Getpagesize())
	ptr := uintptr(unsafe.Pointer(&b[0]))

	start := (ptr + pageSize - 1) &^ (pageSize - 1)
	end := (ptr + uintptr(len(b))) &^ (pageSize - 1)

	if end <= start {
		return 0, false
	}

	length := end - start
	_, _, errno := unix.Syscall(unix.SYS_MADVISE, start, length, uintptr(unix.MADV_DONTNEED))
	if errno != 0 {
		return 0, false
	}
	return int(length), true
}

// JumboBufferArena provides a pre-allocated mmap arena for large network buffers
// (such as Jumbo frames and GSO aggregation buffers), with automatic idle compaction
// and physical page reclamation.
type JumboBufferArena struct {
	mu            sync.Mutex
	data          []byte
	bufferSize    int
	totalBuffers  int
	freeIndices   []int
	borrowed      []bool
	inUse         int
	idleRounds    int
	isDecommitted bool
	closed        bool
}

// NewJumboBufferArena creates a contiguous mmap arena for count buffers of size bufferSize.
func NewJumboBufferArena(count, bufferSize int) (*JumboBufferArena, error) {
	if count <= 0 || bufferSize <= 0 {
		return nil, errors.New("invalid count or bufferSize")
	}

	pageSize := os.Getpagesize()
	totalBytes := count * bufferSize
	totalBytes = (totalBytes + pageSize - 1) &^ (pageSize - 1)

	data, err := unix.Mmap(
		-1,
		0,
		totalBytes,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANON|unix.MAP_PRIVATE,
	)
	if err != nil {
		return nil, err
	}

	freeIndices := make([]int, count)
	for i := 0; i < count; i++ {
		freeIndices[i] = i
	}

	return &JumboBufferArena{
		data:         data,
		bufferSize:   bufferSize,
		totalBuffers: count,
		freeIndices:  freeIndices,
		borrowed:     make([]bool, count),
	}, nil
}

// Get borrows a buffer from the arena.
func (a *JumboBufferArena) Get() ([]byte, int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed || len(a.freeIndices) == 0 {
		return nil, -1, false
	}

	idx := a.freeIndices[len(a.freeIndices)-1]
	a.freeIndices = a.freeIndices[:len(a.freeIndices)-1]
	a.borrowed[idx] = true
	a.inUse++
	a.idleRounds = 0
	a.isDecommitted = false

	offset := idx * a.bufferSize
	return a.data[offset : offset+a.bufferSize], idx, true
}

// Put returns a buffer back to the arena by index.
// Double returns or invalid indices are safely ignored to prevent list corruption and in-use underflow.
func (a *JumboBufferArena) Put(idx int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed || idx < 0 || idx >= a.totalBuffers || !a.borrowed[idx] {
		return
	}

	a.borrowed[idx] = false
	a.freeIndices = append(a.freeIndices, idx)
	a.inUse--
	if a.inUse < 0 {
		a.inUse = 0
	}
}

// Trim yields physical memory pages back to the kernel if the arena remains
// completely idle for threshold rounds. If threshold <= 0, pages are reclaimed immediately.
func (a *JumboBufferArena) Trim(threshold int) (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed || a.inUse > 0 {
		a.idleRounds = 0
		return 0, false
	}

	if threshold <= 0 {
		if a.isDecommitted {
			return 0, false
		}
		freed, ok := ReleasePhysicalPages(a.data)
		if ok {
			a.isDecommitted = true
			return freed, true
		}
		return 0, false
	}

	a.idleRounds++
	if a.idleRounds >= threshold && !a.isDecommitted {
		freed, ok := ReleasePhysicalPages(a.data)
		if ok {
			a.isDecommitted = true
			return freed, true
		}
	}
	return 0, false
}

// Close unmaps the arena memory once every buffer it handed out has been
// returned. Further Get and Trim calls will safely fail. Closing with
// buffers still outstanding is refused — the outstanding slices point into
// the mapping, so munmapping under them turns their next touch into
// SIGSEGV — and the error reports how many are still held so the caller can
// drain and retry.
func (a *JumboBufferArena) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return nil
	}
	if a.inUse > 0 {
		return fmt.Errorf("pool: jumbo buffer arena still has %d buffers outstanding", a.inUse)
	}
	a.closed = true

	if len(a.data) > 0 {
		err := unix.Munmap(a.data)
		a.data = nil
		return err
	}
	return nil
}

// TrimProcessMemory performs a coordinated heap scavenge and OS memory handback.
func TrimProcessMemory() {
	runtime.GC()
	debug.FreeOSMemory()
}
