package main

// FieldSpec unifies the various specs for assembly, disassembly, and doc generation.
type FieldSpec interface {
	Field() byte
	Type() StackType
	OpVersion() uint64
	Note() string
	Version() uint64
}

// fieldSpecMap is something that yields a FieldSpec, given a name for the field
type fieldSpecMap interface {
	get(name string) (FieldSpec, bool)
}

// map txn type names (long and short) to index/enum value
var txnTypeMap = make(map[string]uint64)

// onCompletionMap maps symbolic name to uint64 for assembleInt
var onCompletionMap map[string]uint64

// FieldGroup binds all the info for a field (names, int value, spec access) so
// they can be attached to opcodes and used by doc generation
type FieldGroup struct {
	Name  string
	Doc   string
	Names []string
	specs fieldSpecMap
}

// SpecByName returns a FieldsSpec for a name, respecting the "sparseness" of
// the Names array to hide some names
func (fg *FieldGroup) SpecByName(name string) (FieldSpec, bool) {
	if fs, ok := fg.specs.get(name); ok {
		if fg.Names[fs.Field()] != "" {
			return fs, true
		}
	}
	return nil, false
}
