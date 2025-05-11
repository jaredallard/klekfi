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
	"os"
	"text/tabwriter"
	"time"

	"git.rgst.io/homelab/klefki/internal/db"
	"github.com/spf13/cobra"
)

// newListCommand creates a list [cobra.Command]
func newListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all known machines",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dbc, err := db.New(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to open DB: %w", err)
			}
			defer dbc.Close()

			ms, err := dbc.Machine.Query().All(cmd.Context())
			if err != nil {
				return err
			}
			if len(ms) == 0 {
				fmt.Println("No results found")
				return nil
			}

			tw := tabwriter.NewWriter(os.Stdout, 2, 2, 2, ' ', 0)
			fmt.Fprint(tw, "FINGERPRINT\tCREATED AT\n")
			for _, m := range ms {
				createdAt, err := time.Parse(time.RFC3339, m.CreatedAt)
				if err != nil {
					return fmt.Errorf("failed to parse created_at (%s): %w", m.CreatedAt, err)
				}

				fmt.Fprintf(tw, "%s\t%s\n", m.ID, createdAt.Local())
			}
			return tw.Flush()
		},
	}
}
