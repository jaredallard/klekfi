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
	"git.rgst.io/homelab/klefki/internal/machines"
	"github.com/spf13/cobra"
)

// newNewCommand creates a new [cobra.Command]
func newNewCommand() *cobra.Command {
	// TODO(jaredallard): Support setting the name of the machine.
	return &cobra.Command{
		Use:   "new <machineName>",
		Short: "Create a new machine",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0] // Checked by [cobra.ExactArgs] above.

			dbc, err := db.New(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to open DB: %w", err)
			}
			defer dbc.Close()

			m, err := machines.NewMachine()
			if err != nil {
				return err
			}

			fprint, err := m.Fingerprint()
			if err != nil {
				return err
			}

			privKey, err := m.EncodePrivateKey()
			if err != nil {
				return err
			}

			if err := dbc.Machine.Create().SetName(name).
				SetID(fprint).SetPublicKey(m.PublicKey).
				Exec(cmd.Context()); err != nil {
				return fmt.Errorf("failed to write to DB: %w", err)
			}

			fmt.Println("Fingerprint:", fprint)
			fmt.Println("Private Key:")
			fmt.Println(privKey)
			return nil
		},
	}
}
