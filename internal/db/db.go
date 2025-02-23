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

// Package db contains the DB glue logic.
package db

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect"
	"git.rgst.io/homelab/klefki/internal/db/ent"

	_ "github.com/ncruces/go-sqlite3/driver" // Used by ent.
	_ "github.com/ncruces/go-sqlite3/embed"  // Also used by ent.
)

// New creates a new connection to the DB.
func New(ctx context.Context) (*ent.Client, error) {
	client, err := ent.Open(dialect.SQLite, "file:data/klefkictl.db")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Run the automatic migration tool to create all schema resources.
	if err := client.Schema.Create(ctx); err != nil {
		return nil, fmt.Errorf("failed to run DB migrations: %w", err)
	}

	return client, nil
}
