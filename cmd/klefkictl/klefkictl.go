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

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
)

func main() {
	exitCode := 0
	defer func() { os.Exit(exitCode) }()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	rootCmd := &cobra.Command{
		Use:   "klefkictl",
		Short: "CLI for interacting with klefki",
	}
	rootCmd.AddCommand(
		newNewCommand(),
		newListCommand(),
		newDeleteCommand(),
	)
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitCode = 1
	}
}
