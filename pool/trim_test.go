//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package pool

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPool_ReleasePhysicalPages(t *testing.T) {
	pageSize := os.Getpagesize()
	mem := make([]byte, pageSize*2)

	for i := range mem {
		mem[i] = 0x7a
	}

	freed, ok := ReleasePhysicalPages(mem)
	require.True(t, ok)
	require.Equal(t, len(mem), freed)

	// Memory is zeroed on demand upon read after MADV_DONTNEED
	require.Equal(t, byte(0), mem[0])

	// Re-dirtying succeeds
	mem[0] = 0x99
	require.Equal(t, byte(0x99), mem[0])
}

func TestPool_JumboBufferArena(t *testing.T) {
	bufferSize := 8192
	count := 8

	arena, err := NewJumboBufferArena(count, bufferSize)
	require.NoError(t, err)
	defer func() {
		_ = arena.Close()
	}()

	buf1, idx1, ok := arena.Get()
	require.True(t, ok)
	require.Equal(t, bufferSize, len(buf1))

	// In-use arena should not trim
	freed, trimmed := arena.Trim(1)
	require.False(t, trimmed)
	require.Equal(t, 0, freed)

	arena.Put(idx1)

	// Trim after idle rounds
	for i := 0; i < DefaultTrimThreshold-1; i++ {
		_, trimmed = arena.Trim(DefaultTrimThreshold)
		require.False(t, trimmed)
	}

	freed, trimmed = arena.Trim(DefaultTrimThreshold)
	require.True(t, trimmed)
	require.Positive(t, freed)
}

func TestPool_JumboBufferArena_LifecycleHardening(t *testing.T) {
	// Invalid parameters should return error, not panic
	_, err := NewJumboBufferArena(0, 1024)
	require.Error(t, err)
	_, err = NewJumboBufferArena(4, 0)
	require.Error(t, err)

	arena, err := NewJumboBufferArena(2, 4096)
	require.NoError(t, err)

	_, idx0, ok0 := arena.Get()
	require.True(t, ok0)
	b1, idx1, ok1 := arena.Get()
	require.True(t, ok1)
	require.NotEqual(t, idx0, idx1)

	// Arena exhausted
	_, _, ok2 := arena.Get()
	require.False(t, ok2)

	// Dirty b1
	b1[0] = 0xab

	// Double-Put defense: putting idx0 twice should not corrupt free list or disarm inUse guard
	arena.Put(idx0)
	arena.Put(idx0) // Redundant put ignored

	// idx1 is still held! Trim must NOT release pages even if threshold <= 0
	freed, trimmed := arena.Trim(0)
	require.False(t, trimmed)
	require.Equal(t, 0, freed)
	require.Equal(t, byte(0xab), b1[0], "b1 content must not be wiped by premature trim")

	// Return b1
	arena.Put(idx1)

	// Now completely idle, immediate trim (threshold <= 0) should succeed
	freed, trimmed = arena.Trim(0)
	require.True(t, trimmed)
	require.Positive(t, freed)

	// Close fencing
	err = arena.Close()
	require.NoError(t, err)

	// Subsequent operations must safely return without panic
	_, _, okAfterClose := arena.Get()
	require.False(t, okAfterClose)
	_, trimmedAfterClose := arena.Trim(0)
	require.False(t, trimmedAfterClose)
	arena.Put(0) // Safe no-op

	// Idempotent Close
	err = arena.Close()
	require.NoError(t, err)
}

// TestJumboBufferArenaCloseRefusedWithBuffersOutstanding pins the unmap
// guard: Close must refuse while buffers are still checked out, because the
// outstanding slices point into the mapping and munmapping under them turns
// their next touch into SIGSEGV. After the buffers return, Close succeeds.
func TestJumboBufferArenaCloseRefusedWithBuffersOutstanding(t *testing.T) {
	arena, err := NewJumboBufferArena(8, 8192)
	if err != nil {
		t.Skipf("arena allocation unavailable: %v", err)
	}
	defer func() { _ = arena.Close() }()

	_, idx1, ok := arena.Get()
	if !ok {
		t.Fatal("Get failed")
	}

	if err := arena.Close(); err == nil {
		t.Fatal("Close with a buffer outstanding must be refused, not munmap under live slices")
	}

	arena.Put(idx1)
	if err := arena.Close(); err != nil {
		t.Fatalf("Close after buffers returned: %v", err)
	}
}
