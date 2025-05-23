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

// Package main implements the Klekfi server.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"git.rgst.io/homelab/klefki/internal/server"
)

func main() {
	exitCode := 0
	defer func() { os.Exit(exitCode) }()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	s := (server.Server{})
	go func() {
		if err := s.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "failed to start server: %v\n", err)
			exitCode = 1
			cancel()
		}
	}()

	<-ctx.Done()
	fmt.Println() // better XP for ^C

	if err := s.Close(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to close server: %v\n", err)
		exitCode = 1
		return
	}
}
