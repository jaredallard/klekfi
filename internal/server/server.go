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

// Package server contains the gRPC server logic for the service.
package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"git.rgst.io/homelab/klefki/internal/db"
	"git.rgst.io/homelab/klefki/internal/db/ent"
	"git.rgst.io/homelab/klefki/internal/machines"
	pbgrpcv1 "git.rgst.io/homelab/klefki/internal/server/grpc/generated/go/rgst/klefki/v1"
	"git.rgst.io/homelab/sigtool/v3/sign"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// nopWriteCloser is a no-op [io.WriteCloser]
type nopWriteCloser struct {
	io.Writer
}

// Close implements [io.Closer]
func (nwc nopWriteCloser) Close() error {
	return nil
}

// newNopWriteCloser creates a new nopWriteCloser
func newNopWriteCloser(w io.Writer) *nopWriteCloser {
	return &nopWriteCloser{w}
}

type Session struct {
	// CreatedAt is when the provided session was created. Should be in
	// UTC.
	CreatedAt time.Time

	// ID is the session ID, this is used as an authenticate gate.
	ID uuid.UUID

	// EncKey is the encrypted provided by SubmitKey. If not set, no key
	// has been provided.
	EncKey []byte
}

// Server is a Klefki gRPC server
type Server struct {
	gs *grpc.Server
	db *ent.Client

	// ses is a machine_id -> Session map
	ses   map[string]*Session
	sesMu sync.Mutex

	pbgrpcv1.UnimplementedKlefkiServiceServer
}

// Run starts the server
func (s *Server) Run(ctx context.Context) error {
	s.ses = make(map[string]*Session)

	var err error
	s.db, err = db.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to open DB: %w", err)
	}

	s.gs = grpc.NewServer()
	pbgrpcv1.RegisterKlefkiServiceServer(s.gs, s)
	reflection.Register(s.gs)

	lis, err := net.Listen("tcp", ":5300") //nolint:gosec // Why: This is fine.
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	fmt.Printf("starting gRPC server on %s\n", lis.Addr())
	return s.gs.Serve(lis)
}

// CreateSession implements the CreateSession RPC
func (s *Server) CreateSession(ctx context.Context, req *pbgrpcv1.CreateSessionRequest) (*pbgrpcv1.CreateSessionResponse, error) {
	resp := &pbgrpcv1.CreateSessionResponse{}

	nonce := req.GetNonce()
	sig := req.GetSignature()

	machine, err := s.db.Machine.Get(ctx, req.GetMachineId())
	if err != nil {
		return nil, err
	}

	if err := machines.Verify(machine.PublicKey, sig, nonce); err != nil {
		return nil, err
	}

	spubk, err := sign.PublicKeyFromBytes(machine.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create pub key for encryption: %w", err)
	}

	enc, err := sign.NewEncryptor(nil, 1024)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor instance: %w", err)
	}

	if err := enc.AddRecipient(spubk); err != nil {
		return nil, fmt.Errorf("failed to add instance public key to encryptor: %w", err)
	}

	sessionID := uuid.New()
	var buf bytes.Buffer
	if err := enc.Encrypt(strings.NewReader(sessionID.String()), newNopWriteCloser(&buf)); err != nil {
		return nil, fmt.Errorf("failed to encrypt passphrase: %w", err)
	}
	resp.SetEncSessionId(buf.Bytes())

	s.sesMu.Lock()
	defer s.sesMu.Unlock()

	s.ses[machine.ID] = &Session{
		CreatedAt: time.Now().UTC(),
		ID:        sessionID,
	}

	return resp, nil
}

// ListSessions implements the ListSessions RPC.
func (s *Server) ListSessions(ctx context.Context, _ *pbgrpcv1.ListSessionsRequest) (*pbgrpcv1.ListSessionsResponse, error) {
	resp := &pbgrpcv1.ListSessionsResponse{}

	grpcMachines := make([]*pbgrpcv1.Machine, 0, len(s.ses))
	for machineID := range s.ses {
		machine, err := s.db.Machine.Get(ctx, machineID)
		if err != nil {
			return nil, fmt.Errorf("failed to get machine %q: %w", machineID, err)
		}

		grpcMachines = append(grpcMachines, machines.GRPCMachine(machine))
	}

	resp.SetMachines(grpcMachines)
	return resp, nil
}

// Close closes the server
func (s *Server) Close(_ context.Context) error {
	if s.gs == nil {
		return nil
	}

	fmt.Println("shutting down server")
	s.gs.GracefulStop()
	return s.db.Close()
}
