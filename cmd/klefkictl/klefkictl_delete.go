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
	"fmt"

	"git.rgst.io/homelab/klefki/internal/db"
	"github.com/spf13/cobra"
)

// newDeleteCommand creates a dekete [cobra.Command]
func newDeleteCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <fingerprint>",
		Short: "Delete a known machine by fingerprint",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := db.New(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to open DB: %w", err)
			}
			defer db.Close()

			return db.Machine.DeleteOneID(args[0]).Exec(cmd.Context())
		},
	}
}
