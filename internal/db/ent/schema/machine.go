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

package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// Machine holds the schema definition for the Machine entity.
type Machine struct {
	ent.Schema
}

// Fields of the Machine.
func (Machine) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Comment("Fingerprint of the public key"),
		field.String("name").Comment("User friendly name of this machine (e.g., hostname)").Unique(),
		field.Bytes("public_key").Comment("Public key of the machine"),
		field.String("created_at").Comment("When this machine was added in UTC").Default(time.Now().UTC().Format(time.RFC3339)),
	}
}
