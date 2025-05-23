// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"git.rgst.io/homelab/klefki/internal/db/ent/machine"
	"git.rgst.io/homelab/klefki/internal/db/ent/predicate"
)

// MachineUpdate is the builder for updating Machine entities.
type MachineUpdate struct {
	config
	hooks    []Hook
	mutation *MachineMutation
}

// Where appends a list predicates to the MachineUpdate builder.
func (mu *MachineUpdate) Where(ps ...predicate.Machine) *MachineUpdate {
	mu.mutation.Where(ps...)
	return mu
}

// SetName sets the "name" field.
func (mu *MachineUpdate) SetName(s string) *MachineUpdate {
	mu.mutation.SetName(s)
	return mu
}

// SetNillableName sets the "name" field if the given value is not nil.
func (mu *MachineUpdate) SetNillableName(s *string) *MachineUpdate {
	if s != nil {
		mu.SetName(*s)
	}
	return mu
}

// SetPublicKey sets the "public_key" field.
func (mu *MachineUpdate) SetPublicKey(b []byte) *MachineUpdate {
	mu.mutation.SetPublicKey(b)
	return mu
}

// SetCreatedAt sets the "created_at" field.
func (mu *MachineUpdate) SetCreatedAt(s string) *MachineUpdate {
	mu.mutation.SetCreatedAt(s)
	return mu
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (mu *MachineUpdate) SetNillableCreatedAt(s *string) *MachineUpdate {
	if s != nil {
		mu.SetCreatedAt(*s)
	}
	return mu
}

// Mutation returns the MachineMutation object of the builder.
func (mu *MachineUpdate) Mutation() *MachineMutation {
	return mu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (mu *MachineUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, mu.sqlSave, mu.mutation, mu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (mu *MachineUpdate) SaveX(ctx context.Context) int {
	affected, err := mu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (mu *MachineUpdate) Exec(ctx context.Context) error {
	_, err := mu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (mu *MachineUpdate) ExecX(ctx context.Context) {
	if err := mu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (mu *MachineUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(machine.Table, machine.Columns, sqlgraph.NewFieldSpec(machine.FieldID, field.TypeString))
	if ps := mu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := mu.mutation.Name(); ok {
		_spec.SetField(machine.FieldName, field.TypeString, value)
	}
	if value, ok := mu.mutation.PublicKey(); ok {
		_spec.SetField(machine.FieldPublicKey, field.TypeBytes, value)
	}
	if value, ok := mu.mutation.CreatedAt(); ok {
		_spec.SetField(machine.FieldCreatedAt, field.TypeString, value)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, mu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{machine.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	mu.mutation.done = true
	return n, nil
}

// MachineUpdateOne is the builder for updating a single Machine entity.
type MachineUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *MachineMutation
}

// SetName sets the "name" field.
func (muo *MachineUpdateOne) SetName(s string) *MachineUpdateOne {
	muo.mutation.SetName(s)
	return muo
}

// SetNillableName sets the "name" field if the given value is not nil.
func (muo *MachineUpdateOne) SetNillableName(s *string) *MachineUpdateOne {
	if s != nil {
		muo.SetName(*s)
	}
	return muo
}

// SetPublicKey sets the "public_key" field.
func (muo *MachineUpdateOne) SetPublicKey(b []byte) *MachineUpdateOne {
	muo.mutation.SetPublicKey(b)
	return muo
}

// SetCreatedAt sets the "created_at" field.
func (muo *MachineUpdateOne) SetCreatedAt(s string) *MachineUpdateOne {
	muo.mutation.SetCreatedAt(s)
	return muo
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (muo *MachineUpdateOne) SetNillableCreatedAt(s *string) *MachineUpdateOne {
	if s != nil {
		muo.SetCreatedAt(*s)
	}
	return muo
}

// Mutation returns the MachineMutation object of the builder.
func (muo *MachineUpdateOne) Mutation() *MachineMutation {
	return muo.mutation
}

// Where appends a list predicates to the MachineUpdate builder.
func (muo *MachineUpdateOne) Where(ps ...predicate.Machine) *MachineUpdateOne {
	muo.mutation.Where(ps...)
	return muo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (muo *MachineUpdateOne) Select(field string, fields ...string) *MachineUpdateOne {
	muo.fields = append([]string{field}, fields...)
	return muo
}

// Save executes the query and returns the updated Machine entity.
func (muo *MachineUpdateOne) Save(ctx context.Context) (*Machine, error) {
	return withHooks(ctx, muo.sqlSave, muo.mutation, muo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (muo *MachineUpdateOne) SaveX(ctx context.Context) *Machine {
	node, err := muo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (muo *MachineUpdateOne) Exec(ctx context.Context) error {
	_, err := muo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (muo *MachineUpdateOne) ExecX(ctx context.Context) {
	if err := muo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (muo *MachineUpdateOne) sqlSave(ctx context.Context) (_node *Machine, err error) {
	_spec := sqlgraph.NewUpdateSpec(machine.Table, machine.Columns, sqlgraph.NewFieldSpec(machine.FieldID, field.TypeString))
	id, ok := muo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Machine.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := muo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, machine.FieldID)
		for _, f := range fields {
			if !machine.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != machine.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := muo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := muo.mutation.Name(); ok {
		_spec.SetField(machine.FieldName, field.TypeString, value)
	}
	if value, ok := muo.mutation.PublicKey(); ok {
		_spec.SetField(machine.FieldPublicKey, field.TypeBytes, value)
	}
	if value, ok := muo.mutation.CreatedAt(); ok {
		_spec.SetField(machine.FieldCreatedAt, field.TypeString, value)
	}
	_node = &Machine{config: muo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, muo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{machine.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	muo.mutation.done = true
	return _node, nil
}
