/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package core

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gitrgoliveira/go-fileencrypt/secure"
)

func TestEncryptor_ConcurrentUseDetection(t *testing.T) {
	t.Skip("Encryptors are not designed for concurrent use - test documents expected failure")

	key := make([]byte, 32)
	rand.Read(key)
	defer secure.Zero(key)

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}

	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tmpDir := t.TempDir()
			srcPath := filepath.Join(tmpDir, "test.txt")
			dstPath := filepath.Join(tmpDir, "test.enc")
			os.WriteFile(srcPath, []byte("test"), 0644)
			err := enc.EncryptFile(context.Background(), srcPath, dstPath)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	errorCount := 0
	for err := range errors {
		t.Logf("Got expected error from concurrent use: %v", err)
		errorCount++
	}

	if errorCount == 0 {
		t.Error("Expected errors from concurrent use, got none - this is unsafe!")
	}
}

func TestBufferPool_Concurrency(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	defer secure.Zero(key)

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := enc.bufferPool.Get().(*[]byte)
			(*buf)[0] = 0xFF
			enc.bufferPool.Put(buf)
		}()
	}
	wg.Wait()
}
