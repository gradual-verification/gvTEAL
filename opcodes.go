package main

import (
	"fmt"
	"strings"
)

type typedList struct {
	Types   StackTypes
	Effects string
}

// Proto describes the "stack behavior" of an opcode, what it pops as arguments
// and pushes onto the stack as return values.
type Proto struct {
	Arg    typedList // what gets popped from the stack
	Return typedList // what gets pushed to the stack
}

type evalFunc func(cx *EvalContext) error
type checkFunc func(cx *EvalContext) error

type linearCost struct {
	baseCost  int
	chunkCost int
	chunkSize int
	depth     int
}

// immType describes the immediate arguments to an opcode
type immKind byte

type immediate struct {
	Name  string
	kind  immKind
	Group *FieldGroup

	// If non-nil, always 256 long, so cost can be checked before eval
	fieldCosts []int
}

// OpDetails records details such as non-standard costs, immediate arguments, or
// dynamic layout controlled by a check function. These objects are mostly built
// with constructor functions, so it's cleaner to have defaults set here, rather
// than in line after line of OpSpecs.
type OpDetails struct {
	asm    asmFunc    // assemble the op
	check  checkFunc  // static check bytecode (and determine size)
	refine refineFunc // refine arg/return types based on ProgramKnowledge at assembly time

	Modes RunMode // all modes that opcode can run in. i.e (cx.mode & Modes) != 0 allows

	FullCost   linearCost  // if non-zero, the cost of the opcode, no immediates matter
	Size       int         // if non-zero, the known size of opcode. if 0, check() determines.
	Immediates []immediate // details of each immediate arg to opcode

	trusted bool // if `trusted`, don't check stack effects. they are more complicated than simply checking the opcode prototype.
}

const (
	immByte immKind = iota
	immInt8
	immLabel
	immInt
	immBytes
	immInts
	immBytess // "ss" not a typo.  Multiple "bytes"
	immLabels
)

// LogicVersion defines default assembler and max eval versions
const LogicVersion = 9

// backBranchEnabledVersion is the first version of TEAL where branches could
// go back (and cost accounting was done during execution)
const backBranchEnabledVersion = 4

// direct opcode bytes
var opsByOpcode [LogicVersion + 1][256]OpSpec

// Keeps track of all field names accessible in each version
var fieldNames [LogicVersion + 1]map[string]bool

// OpsByName map for each version, mapping opcode name to OpSpec
var OpsByName [LogicVersion + 1]map[string]OpSpec

func (ik immKind) String() string {
	switch ik {
	case immByte:
		return "uint8"
	case immInt8:
		return "int8"
	case immLabel:
		return "int16 (big-endian)"
	case immInt:
		return "varuint"
	case immBytes:
		return "varuint length, bytes"
	case immInts:
		return fmt.Sprintf("varuint count, [%s ...]", immInt.String())
	case immBytess: // "ss" not a typo.  Multiple "bytes"
		return fmt.Sprintf("varuint count, [%s ...]", immBytes.String())
	case immLabels:
		return fmt.Sprintf("varuint count, [%s ...]", immLabel.String())
	}
	return "unknown"
}

// OpSpec defines an opcode
type OpSpec struct {
	Opcode byte
	Name   string
	op     evalFunc // evaluate the op
	Proto
	Version   uint64 // AVM version opcode introduced
	OpDetails        // Special cost or bytecode layout considerations
}

// AlwaysExits is true iff the opcode always ends the program.
func (spec *OpSpec) AlwaysExits() bool {
	return len(spec.Return.Types) == 1 && spec.Return.Types[0].AVMType == avmNone
}

func (spec *OpSpec) deadens() bool {
	switch spec.Name {
	case "b", "callsub", "retsub", "err", "return":
		return true
	default:
		return false
	}
}

// OpSpecs is the table of operations that can be assembled and evaluated.
//
// Any changes should be reflected in README_in.md which serves as the language spec.
//
// Note: assembly can specialize an Any return type if known at
// assembly-time, with ops.returns()
var OpSpecs = []OpSpec{
	// {0x00, "err", opErr, proto(":x"), 1, detDefault()},
	// {0x01, "sha256", opSHA256, proto("b:H"), 1, costly(7)},
	// {0x02, "keccak256", opKeccak256, proto("b:H"), 1, costly(26)},
	// {0x03, "sha512_256", opSHA512_256, proto("b:H"), 1, costly(9)},

	{0x08, "+", opPlus, proto("ii:i"), 1, detDefault()},
	{0x12, "==", opEq, proto("aa:T"), 1, typed(typeEquals)},
	{0x43, "return", opReturn, proto("i:x"), 1, detDefault()},
}

type sortByOpcode []OpSpec

func (a sortByOpcode) Len() int           { return len(a) }
func (a sortByOpcode) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a sortByOpcode) Less(i, j int) bool { return a[i].Opcode < a[j].Opcode }

func proto(signature string, effects ...string) Proto {
	parts := strings.Split(signature, ":")
	if len(parts) != 2 {
		panic(signature)
	}
	var argEffect, retEffect string
	switch len(effects) {
	case 0:
		// will be generated
	case 1:
		retEffect = effects[0]
	case 2:
		argEffect = effects[0]
		retEffect = effects[1]
	default:
		panic(effects)
	}
	return Proto{
		Arg:    typedList{parseStackTypes(parts[0]), argEffect},
		Return: typedList{parseStackTypes(parts[1]), retEffect},
	}
}

func detDefault() OpDetails {
	return OpDetails{asmDefault, nil, nil, modeAny, linearCost{baseCost: 1}, 1, nil, false}
}

func typed(typer refineFunc) OpDetails {
	d := detDefault()
	d.refine = typer
	return d
}

func (d OpDetails) typed(typer refineFunc) OpDetails {
	d.refine = typer
	return d
}

func assembler(asm asmFunc) OpDetails {
	d := detDefault()
	d.asm = asm
	return d
}

func init() {
	// First, initialize baseline v1 opcodes.
	// Zero (empty) version is an alias for v1 opcodes and needed for compatibility with v1 code.
	OpsByName[0] = make(map[string]OpSpec, 256)
	OpsByName[1] = make(map[string]OpSpec, 256)

	for _, oi := range OpSpecs {
		if oi.Version == 1 {
			cp := oi
			cp.Version = 0
			opsByOpcode[0][oi.Opcode] = cp
			OpsByName[0][oi.Name] = cp

			opsByOpcode[1][oi.Opcode] = oi
			OpsByName[1][oi.Name] = oi
		}
	}

	// Start from v2 and higher,
	// copy lower version opcodes and overwrite matching version
	for v := uint64(2); v <= evalMaxVersion; v++ {
		OpsByName[v] = make(map[string]OpSpec, 256)

		// Copy opcodes from lower version
		for opName, oi := range OpsByName[v-1] {
			OpsByName[v][opName] = oi
		}
		for op, oi := range opsByOpcode[v-1] {
			opsByOpcode[v][op] = oi
		}

		// Update tables with opcodes from the current version
		for _, oi := range OpSpecs {
			if oi.Version == v {
				opsByOpcode[v][oi.Opcode] = oi
				OpsByName[v][oi.Name] = oi
			}
		}
	}

	for v := 0; v <= LogicVersion; v++ {
		fieldNames[v] = make(map[string]bool)
		for _, spec := range OpsByName[v] {
			for _, imm := range spec.Immediates {
				if imm.Group != nil {
					for _, fieldName := range imm.Group.Names {
						fieldNames[v][fieldName] = true
					}
				}
			}
		}
	}
}
