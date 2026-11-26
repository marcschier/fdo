// Copyright (c) marcschier. Licensed under the MIT License.

package cose

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

const fixtureExchangeLimit = 64

// The HTTP handler reloads the same session key from SQLite on each request.
// The isolated process allows one key and one outstanding request; never reset
// its counters or start another exchange in the same process.
var fixtureGcmState struct {
	sync.Mutex
	key      [sha256.Size]byte
	started  bool
	received uint32
	sent     uint32
}

type fixtureGcm struct {
	aead cipher.AEAD
	key  [sha256.Size]byte
}

func newFixtureGcm(key []byte) (Crypter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &fixtureGcm{aead: aead, key: sha256.Sum256(key)}, nil
}

func fixtureNonce(role byte, counter uint32) [12]byte {
	var nonce [12]byte
	nonce[7] = role
	binary.BigEndian.PutUint32(nonce[8:], counter)
	return nonce
}

func (c *fixtureGcm) Encrypt(_ io.Reader, plaintext, aad []byte) ([]byte, HeaderMap, error) {
	state := &fixtureGcmState
	state.Lock()
	defer state.Unlock()
	if aad == nil || !state.started || state.key != c.key ||
		state.sent >= fixtureExchangeLimit || state.received != state.sent+1 {
		return nil, nil, errors.New("fixture GCM response is out of turn or outside the single-session limit")
	}

	nonce := fixtureNonce(1, state.sent)
	state.sent++
	return c.aead.Seal(nil, nonce[:], plaintext, aad), HeaderMap{IvLabel: nonce[:]}, nil
}

func (c *fixtureGcm) Decrypt(_ io.Reader, ciphertext, aad []byte, headers HeaderParser) ([]byte, error) {
	state := &fixtureGcmState
	state.Lock()
	defer state.Unlock()
	if aad == nil || (state.started && state.key != c.key) ||
		state.received >= fixtureExchangeLimit || state.received != state.sent {
		return nil, errors.New("fixture GCM request is out of turn or outside the single-session limit")
	}

	var nonce []byte
	found, err := headers.Parse(IvLabel, &nonce)
	if err != nil {
		return nil, err
	}
	expected := fixtureNonce(0, state.received)
	if !found || !bytes.Equal(nonce, expected[:]) {
		return nil, errors.New("fixture GCM request does not match the next Device nonce")
	}
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	state.key = c.key
	state.started = true
	state.received++
	return plaintext, nil
}
