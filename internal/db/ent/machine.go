// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"git.rgst.io/homelab/klefki/internal/db/ent/machine"
)

// Machine is the model entity for the Machine schema.
type Machine struct {
	config `json:"-"`
	// ID of the ent.
	// Fingerprint of the public key
	ID string `json:"id,omitempty"`
	// Public key of the machine
	PublicKey []byte `json:"public_key,omitempty"`
	// When this machine was added in UTC
	CreatedAt    string `json:"created_at,omitempty"`
	selectValues sql.SelectValues
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Machine) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case machine.FieldPublicKey:
			values[i] = new([]byte)
		case machine.FieldID, machine.FieldCreatedAt:
			values[i] = new(sql.NullString)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Machine fields.
func (m *Machine) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case machine.FieldID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value.Valid {
				m.ID = value.String
			}
		case machine.FieldPublicKey:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field public_key", values[i])
			} else if value != nil {
				m.PublicKey = *value
			}
		case machine.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				m.CreatedAt = value.String
			}
		default:
			m.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the Machine.
// This includes values selected through modifiers, order, etc.
func (m *Machine) Value(name string) (ent.Value, error) {
	return m.selectValues.Get(name)
}

// Update returns a builder for updating this Machine.
// Note that you need to call Machine.Unwrap() before calling this method if this Machine
// was returned from a transaction, and the transaction was committed or rolled back.
func (m *Machine) Update() *MachineUpdateOne {
	return NewMachineClient(m.config).UpdateOne(m)
}

// Unwrap unwraps the Machine entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (m *Machine) Unwrap() *Machine {
	_tx, ok := m.config.driver.(*txDriver)
	if !ok {
		panic("ent: Machine is not a transactional entity")
	}
	m.config.driver = _tx.drv
	return m
}

// String implements the fmt.Stringer.
func (m *Machine) String() string {
	var builder strings.Builder
	builder.WriteString("Machine(")
	builder.WriteString(fmt.Sprintf("id=%v, ", m.ID))
	builder.WriteString("public_key=")
	builder.WriteString(fmt.Sprintf("%v", m.PublicKey))
	builder.WriteString(", ")
	builder.WriteString("created_at=")
	builder.WriteString(m.CreatedAt)
	builder.WriteByte(')')
	return builder.String()
}

// Machines is a parsable slice of Machine.
type Machines []*Machine
