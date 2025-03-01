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

package server

import (
	"context"
	"crypto/ed25519"

	pbgrpcv1 "git.rgst.io/homelab/klefki/internal/server/grpc/generated/go/rgst/klefki/v1"
)

// AuthChallenge is an authentication challenge.
type AuthChallenge struct {
	// MachineID is the ID of the machine that sent this request
	// (fingerprint).
	MachineID string `json:"machine_id"`

	// Signature is an ED25519 signature of the provided message.
	Signature []byte `json:"signature"`

	// Nonce is a randomly generated string that corresponds to the
	// provided signature.
	Nonce string `json:"nonce"`
}

// ValidateAuth determines if the auth presented is valid or not.
func (s *Server) ValidateAuth(ctx context.Context, req *pbgrpcv1.GetKeyRequest) bool {
	// Get the public key for this node.
	m, err := s.db.Machine.Get(ctx, req.GetMachineId())
	if err != nil {
		return false
	}

	return ed25519.Verify(m.PublicKey, []byte(req.GetNonce()), req.GetSignature())
}
