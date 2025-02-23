// Code generated by ent, DO NOT EDIT.

package migrate

import (
	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"
)

var (
	// MachinesColumns holds the columns for the "machines" table.
	MachinesColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString},
		{Name: "public_key", Type: field.TypeString},
	}
	// MachinesTable holds the schema information for the "machines" table.
	MachinesTable = &schema.Table{
		Name:       "machines",
		Columns:    MachinesColumns,
		PrimaryKey: []*schema.Column{MachinesColumns[0]},
	}
	// Tables holds all the tables in the schema.
	Tables = []*schema.Table{
		MachinesTable,
	}
)

func init() {
}
