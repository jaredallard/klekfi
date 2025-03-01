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
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"text/tabwriter"

	pbgrpcv1 "git.rgst.io/homelab/klefki/internal/server/grpc/generated/go/rgst/klefki/v1"

	"git.rgst.io/homelab/klefki/internal/machines"
	"git.rgst.io/homelab/sigtool/v3/sign"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// newRequestsCommand creates a requests [cobra.Command]
func newRequestsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "requests",
		Short: "Make requests to a klefki server",
	}
	cmd.AddCommand(
		newGetKeyRequestCommand(),
		newListSessionsCommand(),
	)
	return cmd
}

// newGetKeyRequestCommand creates a getkeyrequest [cobra.Command]
func newGetKeyRequestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "getkeyrequest",
		Short: "Get the passphrase for the given machine",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			privKeyPath := cmd.Flag("priv-key").Value.String()

			privKeyByt, err := os.ReadFile(privKeyPath)
			if err != nil {
				return err
			}

			pk, err := machines.DecodePrivateKey(privKeyByt)
			if err != nil {
				return err
			}

			machineID, err := machines.Fingerprint(pk.Public().(ed25519.PublicKey))
			if err != nil {
				return fmt.Errorf("failed to get fingerprint for key: %w", err)
			}

			spk, err := sign.PrivateKeyFromBytes(pk)
			if err != nil {
				return fmt.Errorf("failed to create private key for decryption: %w", err)
			}

			fmt.Printf("Sending GetKeyRequest: machine_id=%s\n", machineID)

			// TODO(jaredallard): Make a client
			conn, err := grpc.NewClient("127.0.0.1:5300", grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				return fmt.Errorf("failed to connect to klefki server: %w", err)
			}
			defer conn.Close()

			client := pbgrpcv1.NewKlefkiServiceClient(conn)

			req := &pbgrpcv1.CreateSessionRequest{}
			req.SetMachineId(machineID)
			req.SetNonce("FIXME")
			req.SetSignature(ed25519.Sign(pk, []byte(req.GetNonce())))

			resp, err := client.CreateSession(cmd.Context(), req)
			if err != nil {
				return fmt.Errorf("failed to get key from server: %w", err)
			}

			encSessionID := resp.GetEncSessionId()
			dec, err := sign.NewDecryptor(bytes.NewReader(encSessionID))
			if err != nil {
				return fmt.Errorf("failed to create decryptor: %w", err)
			}
			if err := dec.SetPrivateKey(spk, nil); err != nil {
				return fmt.Errorf("failed to set private key on decryptor: %w", err)
			}
			var buf bytes.Buffer
			if err := dec.Decrypt(&buf); err != nil {
				return fmt.Errorf("failed to decrypt session ID: %w", err)
			}

			sessionID := buf.String()
			fmt.Println(sessionID)
			return nil
		},
	}
	flags := cmd.Flags()
	flags.String("priv-key", "", "path to private key")
	return cmd
}

// newListSessionsCommand creates a listsessions [cobra.Command]
func newListSessionsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "listsessions",
		Short: "Return a list of all machines waiting for a key to be provided",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// TODO(jaredallard): Make a client
			conn, err := grpc.NewClient("127.0.0.1:5300", grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				return fmt.Errorf("failed to connect to klefki server: %w", err)
			}
			defer conn.Close()

			client := pbgrpcv1.NewKlefkiServiceClient(conn)
			resp, err := client.ListSessions(cmd.Context(), &pbgrpcv1.ListSessionsRequest{})
			if err != nil {
				return fmt.Errorf("failed to get key from server: %w", err)
			}

			machines := resp.GetMachines()
			if len(machines) == 0 {
				fmt.Println("No results found")
				return nil
			}

			tw := tabwriter.NewWriter(os.Stdout, 2, 2, 2, ' ', 0)
			fmt.Fprint(tw, "FINGERPRINT\n")
			for _, m := range machines {
				fmt.Fprintf(tw, "%s\n", m.GetId())
			}
			return tw.Flush()
		},
	}
}
