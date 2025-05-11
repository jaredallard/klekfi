// Copyright (C) 2025 klefki contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0

// Package machines contains all of the code for creating and managing
// machines.
package machines

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sync"

	"git.rgst.io/homelab/klefki/internal/db/ent"
	pbgrpcv1 "git.rgst.io/homelab/klefki/internal/server/grpc/generated/go/rgst/klefki/v1"
)

// Fingerprint returns a fingerprint of the provided key.
func Fingerprint(pub ed25519.PublicKey) (string, error) {
	hasher := sha256.New()
	if _, err := hasher.Write(pub); err != nil {
		return "", fmt.Errorf("failed to hash provided public key: %w", err)
	}
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(hasher.Sum(nil)), nil
}

// Machine is a known machine containing PKI used by it.
type Machine struct {
	fprintOnce  sync.Once
	fingerprint string

	// PublicKey is the public key for this machine. This is always set
	// when initialized through [MachineFromDB] or [Machine].
	PublicKey ed25519.PublicKey

	// PrivateKey is the private key for this machine. This is normally
	// not set instead only when [NewMachine] is called.
	PrivateKey ed25519.PrivateKey
}

// String returns a string version of the machine containing only the
// fingerprint, if obtainable.
func (m *Machine) String() string {
	fprint, err := m.Fingerprint()
	if err != nil {
		fprint = fmt.Sprintf("<failed to calculate: %v>", err)
	}

	return "Machine<" + fprint + ">"
}

// Fingerprint returns the fingerprint of the machine as calculated from
// the public key. This is calculated exactly once. If m.fingerprint is
// already set, this immediately returns that value instead of
// calculating it.
func (m *Machine) Fingerprint() (string, error) {
	var err error
	m.fprintOnce.Do(func() {
		if m.fingerprint != "" {
			return // NOOP if already set.
		}
		m.fingerprint, err = Fingerprint(m.PublicKey)
	})
	if err != nil {
		return "", fmt.Errorf("failed to calculate fingerprint: %w", err)
	}

	return m.fingerprint, nil
}

// EncodePrivateKey returns a X509 PEM encoded private key for the
// ed25519 private key of this machine.
func (m *Machine) EncodePrivateKey() (string, error) {
	privKey, err := x509.MarshalPKCS8PrivateKey(m.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	encoded := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: privKey})
	return string(encoded), nil
}

// EncodePublicKey returns a X509 PEM encoded public key for the
// ed25519 public key of this machine.
func (m *Machine) EncodePublicKey() (string, error) {
	pubKey, err := x509.MarshalPKIXPublicKey(m.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	encoded := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: pubKey})
	return string(encoded), nil
}

// MachineFromDB creates a [Machine] from a [ent.Machine]. Note that the
// private key will never be set in this case as it is no longer known.
func MachineFromDB(m *ent.Machine) *Machine {
	return &Machine{fingerprint: m.ID, PublicKey: ed25519.PublicKey(m.PublicKey)}
}

// NewMachine creates a new [Machine] with the private key included.
func NewMachine() (*Machine, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
	}

	return &Machine{PublicKey: pub, PrivateKey: priv}, nil
}

// DecodePrivateKey decodes a private key that was encoded by
// [Machine.EncodePrivateKey].
func DecodePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, fmt.Errorf("failed to parse private key as PEM encoded data")
	}
	if b.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("expected type \"ED25519 PRIVATE KEY\", got %s", b.Type)
	}

	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	pk, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519.PrivateKey, got %T", k)
	}
	return pk, nil
}

// Verify takes the provided pubKey and determines if the provided
// signature was made by it, for the nonce. A nil error is success.
func Verify(pubKey ed25519.PublicKey, sig []byte, nonce string) error {
	if ed25519.Verify(pubKey, []byte(nonce), sig) {
		return nil
	}

	return fmt.Errorf("invalid signature")
}

// GRPCMachine converts a [ent.Machine] into a [pbgrpcv1.Machine].
func GRPCMachine(m *ent.Machine) *pbgrpcv1.Machine {
	return (&pbgrpcv1.Machine_builder{
		Id:        &m.ID,
		PublicKey: m.PublicKey,
	}).Build()
}
