// Code generated by ent, DO NOT EDIT.

package machine

import (
	"entgo.io/ent/dialect/sql"
	"git.rgst.io/homelab/klefki/internal/db/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id string) predicate.Machine {
	return predicate.Machine(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id string) predicate.Machine {
	return predicate.Machine(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id string) predicate.Machine {
	return predicate.Machine(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...string) predicate.Machine {
	return predicate.Machine(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...string) predicate.Machine {
	return predicate.Machine(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id string) predicate.Machine {
	return predicate.Machine(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id string) predicate.Machine {
	return predicate.Machine(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id string) predicate.Machine {
	return predicate.Machine(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id string) predicate.Machine {
	return predicate.Machine(sql.FieldLTE(FieldID, id))
}

// IDEqualFold applies the EqualFold predicate on the ID field.
func IDEqualFold(id string) predicate.Machine {
	return predicate.Machine(sql.FieldEqualFold(FieldID, id))
}

// IDContainsFold applies the ContainsFold predicate on the ID field.
func IDContainsFold(id string) predicate.Machine {
	return predicate.Machine(sql.FieldContainsFold(FieldID, id))
}

// PublicKey applies equality check predicate on the "public_key" field. It's identical to PublicKeyEQ.
func PublicKey(v []byte) predicate.Machine {
	return predicate.Machine(sql.FieldEQ(FieldPublicKey, v))
}

// CreatedAt applies equality check predicate on the "created_at" field. It's identical to CreatedAtEQ.
func CreatedAt(v string) predicate.Machine {
	return predicate.Machine(sql.FieldEQ(FieldCreatedAt, v))
}

// PublicKeyEQ applies the EQ predicate on the "public_key" field.
func PublicKeyEQ(v []byte) predicate.Machine {
	return predicate.Machine(sql.FieldEQ(FieldPublicKey, v))
}

// PublicKeyNEQ applies the NEQ predicate on the "public_key" field.
func PublicKeyNEQ(v []byte) predicate.Machine {
	return predicate.Machine(sql.FieldNEQ(FieldPublicKey, v))
}

// PublicKeyIn applies the In predicate on the "public_key" field.
func PublicKeyIn(vs ...[]byte) predicate.Machine {
	return predicate.Machine(sql.FieldIn(FieldPublicKey, vs...))
}

// PublicKeyNotIn applies the NotIn predicate on the "public_key" field.
func PublicKeyNotIn(vs ...[]byte) predicate.Machine {
	return predicate.Machine(sql.FieldNotIn(FieldPublicKey, vs...))
}

// PublicKeyGT applies the GT predicate on the "public_key" field.
func PublicKeyGT(v []byte) predicate.Machine {
	return predicate.Machine(sql.FieldGT(FieldPublicKey, v))
}

// PublicKeyGTE applies the GTE predicate on the "public_key" field.
func PublicKeyGTE(v []byte) predicate.Machine {
	return predicate.Machine(sql.FieldGTE(FieldPublicKey, v))
}

// PublicKeyLT applies the LT predicate on the "public_key" field.
func PublicKeyLT(v []byte) predicate.Machine {
	return predicate.Machine(sql.FieldLT(FieldPublicKey, v))
}

// PublicKeyLTE applies the LTE predicate on the "public_key" field.
func PublicKeyLTE(v []byte) predicate.Machine {
	return predicate.Machine(sql.FieldLTE(FieldPublicKey, v))
}

// CreatedAtEQ applies the EQ predicate on the "created_at" field.
func CreatedAtEQ(v string) predicate.Machine {
	return predicate.Machine(sql.FieldEQ(FieldCreatedAt, v))
}

// CreatedAtNEQ applies the NEQ predicate on the "created_at" field.
func CreatedAtNEQ(v string) predicate.Machine {
	return predicate.Machine(sql.FieldNEQ(FieldCreatedAt, v))
}

// CreatedAtIn applies the In predicate on the "created_at" field.
func CreatedAtIn(vs ...string) predicate.Machine {
	return predicate.Machine(sql.FieldIn(FieldCreatedAt, vs...))
}

// CreatedAtNotIn applies the NotIn predicate on the "created_at" field.
func CreatedAtNotIn(vs ...string) predicate.Machine {
	return predicate.Machine(sql.FieldNotIn(FieldCreatedAt, vs...))
}

// CreatedAtGT applies the GT predicate on the "created_at" field.
func CreatedAtGT(v string) predicate.Machine {
	return predicate.Machine(sql.FieldGT(FieldCreatedAt, v))
}

// CreatedAtGTE applies the GTE predicate on the "created_at" field.
func CreatedAtGTE(v string) predicate.Machine {
	return predicate.Machine(sql.FieldGTE(FieldCreatedAt, v))
}

// CreatedAtLT applies the LT predicate on the "created_at" field.
func CreatedAtLT(v string) predicate.Machine {
	return predicate.Machine(sql.FieldLT(FieldCreatedAt, v))
}

// CreatedAtLTE applies the LTE predicate on the "created_at" field.
func CreatedAtLTE(v string) predicate.Machine {
	return predicate.Machine(sql.FieldLTE(FieldCreatedAt, v))
}

// CreatedAtContains applies the Contains predicate on the "created_at" field.
func CreatedAtContains(v string) predicate.Machine {
	return predicate.Machine(sql.FieldContains(FieldCreatedAt, v))
}

// CreatedAtHasPrefix applies the HasPrefix predicate on the "created_at" field.
func CreatedAtHasPrefix(v string) predicate.Machine {
	return predicate.Machine(sql.FieldHasPrefix(FieldCreatedAt, v))
}

// CreatedAtHasSuffix applies the HasSuffix predicate on the "created_at" field.
func CreatedAtHasSuffix(v string) predicate.Machine {
	return predicate.Machine(sql.FieldHasSuffix(FieldCreatedAt, v))
}

// CreatedAtEqualFold applies the EqualFold predicate on the "created_at" field.
func CreatedAtEqualFold(v string) predicate.Machine {
	return predicate.Machine(sql.FieldEqualFold(FieldCreatedAt, v))
}

// CreatedAtContainsFold applies the ContainsFold predicate on the "created_at" field.
func CreatedAtContainsFold(v string) predicate.Machine {
	return predicate.Machine(sql.FieldContainsFold(FieldCreatedAt, v))
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.Machine) predicate.Machine {
	return predicate.Machine(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.Machine) predicate.Machine {
	return predicate.Machine(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.Machine) predicate.Machine {
	return predicate.Machine(sql.NotPredicates(p))
}
