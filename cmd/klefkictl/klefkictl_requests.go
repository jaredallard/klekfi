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
	"strings"
	"text/tabwriter"

	pbgrpcv1 "git.rgst.io/homelab/klefki/internal/server/grpc/generated/go/rgst/klefki/v1"
	"git.rgst.io/homelab/klefki/pkg/client"

	"git.rgst.io/homelab/klefki/internal/machines"
	"git.rgst.io/homelab/sigtool/v3/sign"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
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

// newRequestsCommand creates a requests [cobra.Command]
func newRequestsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "requests",
		Short: "Make requests to a klefki server",
	}
	cmd.AddCommand(
		newGetKeyCommand(),
		newListSessionsCommand(),
		newSubmitKeyCommand(),
	)
	flags := cmd.Flags()
	flags.String("hostname", "127.0.0.1:5300", "hostname of the klefki server to connect to")
	return cmd
}

// newGetKeyCommand creates a getkeyrequest [cobra.Command]
func newGetKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "getkey",
		Short: "Get the passphrase for the given machine",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			privKeyPath := cmd.Flag("priv-key").Value.String()
			hostname := cmd.Parent().Flag("hostname").Value.String()

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

			kc, kcclose, err := client.Dial(hostname)
			if err != nil {
				return err
			}
			defer kcclose() //nolint:errcheck // Why: Btiest effort

			tsResp, err := kc.GetTime(cmd.Context(), &pbgrpcv1.GetTimeRequest{})
			if err != nil {
				return fmt.Errorf("failed to connect to server to get time: %w", err)
			}

			req := &pbgrpcv1.GetKeyRequest{}
			req.SetMachineId(machineID)
			req.SetNonce(uuid.New().String())
			req.SetSignedAt(tsResp.GetTime())
			req.SetSignature(ed25519.Sign(pk, []byte(req.GetNonce())))

			resp, err := kc.GetKey(cmd.Context(), req)
			if err != nil {
				return fmt.Errorf("failed to get key from server: %w", err)
			}

			dec, err := sign.NewDecryptor(bytes.NewReader(resp.GetEncKey()))
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

			fmt.Println(buf.String())
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
			kc, kcclose, err := client.Dial(cmd.Parent().Flag("hostname").Value.String())
			if err != nil {
				return err
			}
			defer kcclose() //nolint:errcheck // Why: Best effort

			resp, err := kc.ListSessions(cmd.Context(), &pbgrpcv1.ListSessionsRequest{})
			if err != nil {
				return fmt.Errorf("failed to get key from server: %w", err)
			}

			machines := resp.GetMachines()
			if len(machines) == 0 {
				fmt.Println("No results found")
				return nil
			}

			tw := tabwriter.NewWriter(os.Stdout, 2, 2, 2, ' ', 0)
			fmt.Fprint(tw, "FINGERPRINT\tLAST ASKED\n")
			for _, m := range machines {
				fmt.Fprintf(tw, "%s\t%s\n", m.GetId(), m.GetLastAsked())
			}
			return tw.Flush()
		},
	}
}

// newSubmitKeyCommand creates a submitekey [cobra.Command]
func newSubmitKeyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "submitkey <machineID> <passphrase>",
		Short: "Submit a passphrase to a given machine by its ID",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			machineID := args[0]
			// TODO(jaredallard): don't expect to be passed as an arg
			passphrase := args[1]

			kc, kcclose, err := client.Dial(cmd.Parent().Flag("hostname").Value.String())
			if err != nil {
				return err
			}
			defer kcclose() //nolint:errcheck // Why: Best effort

			resp, err := kc.ListSessions(cmd.Context(), &pbgrpcv1.ListSessionsRequest{})
			if err != nil {
				return fmt.Errorf("failed to get key from server: %w", err)
			}

			machines := resp.GetMachines()

			var machine *pbgrpcv1.Machine
			for _, m := range machines {
				if m.GetId() == machineID {
					machine = m
					break
				}
			}
			if machine == nil {
				return fmt.Errorf("no sessions found for %q", machineID)
			}

			pubKey, err := sign.PublicKeyFromBytes(machine.GetPublicKey())
			if err != nil {
				return fmt.Errorf("failed to convert machine's public key to encryption public key: %w", err)
			}

			enc, err := sign.NewEncryptor(nil, 1024)
			if err != nil {
				return fmt.Errorf("failed to create decryptor: %w", err)
			}

			if err := enc.AddRecipient(pubKey); err != nil {
				return fmt.Errorf("failed to set private key on decryptor: %w", err)
			}

			var buf bytes.Buffer
			if err := enc.Encrypt(strings.NewReader(passphrase), newNopWriteCloser(&buf)); err != nil {
				return fmt.Errorf("failed to decrypt session ID: %w", err)
			}

			req := &pbgrpcv1.SubmitKeyRequest{}
			req.SetEncKey(buf.Bytes())
			req.SetMachineId(machineID)
			_, err = kc.SubmitKey(cmd.Context(), req)
			return err
		},
	}
}
