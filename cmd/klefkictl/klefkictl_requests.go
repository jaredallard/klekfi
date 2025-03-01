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
	"io"
	"os"

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
	cmd.AddCommand(newGetKeyRequestCommand())
	return cmd
}

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

			req := &pbgrpcv1.GetKeyRequest{}
			req.SetMachineId(machineID)
			req.SetNonce("FIXME")
			req.SetSignature(ed25519.Sign(pk, []byte(req.GetNonce())))

			resp, err := client.GetKey(cmd.Context(), req)
			if err != nil {
				return fmt.Errorf("failed to get key from server: %w", err)
			}

			dec, err := sign.NewDecryptor(bytes.NewReader(resp.GetKey()))
			if err != nil {
				return fmt.Errorf("failed to create decryptor: %w", err)
			}
			if err := dec.SetPrivateKey(spk, nil); err != nil {
				return fmt.Errorf("failed to set private key on decryptor: %w", err)
			}
			return dec.Decrypt(os.Stdout)
		},
	}
	flags := cmd.Flags()
	flags.String("priv-key", "", "path to private key")
	return cmd
}
