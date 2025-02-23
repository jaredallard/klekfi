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
	"context"
	"fmt"
	"net"

	pbgrpcv1 "git.rgst.io/homelab/klefki/internal/server/grpc/generated/go/rgst/klefki/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Server is a Klefki gRPC server
type Server struct {
	gs *grpc.Server
	pbgrpcv1.UnimplementedKlefkiServiceServer
}

// Run starts the server
func (s *Server) Run(_ context.Context) error {
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

// Close closes the server
func (s *Server) Close(_ context.Context) error {
	if s.gs == nil {
		return nil
	}

	fmt.Println("shutting down server")

	s.gs.GracefulStop()
	return nil
}
