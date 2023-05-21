package main

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strings"
)

// evalMaxVersion is the max version we can interpret and run
const evalMaxVersion = LogicVersion

// avmType describes the type of a value on the operand stack
// avmTypes are a subset of StackTypes
type avmType byte

// StackType describes the type of a value on the operand stack
type StackType struct {
	Name    string // alias (address, boolean, ...) or derived name [5]byte
	AVMType avmType
	Bound   [2]uint64 // represents max/min value for uint64 or max/min length for byte[]
}

func (sv stackValue) avmType() avmType {
	if sv.Bytes != nil {
		return avmBytes
	}
	return avmUint64
}

func (sv stackValue) stackType() StackType {
	if sv.Bytes != nil {
		return NewStackType(sv.avmType(), static(uint64(len(sv.Bytes))))
	}
	return NewStackType(sv.avmType(), static(sv.Uint))
}

// StackTypes is an alias for a list of StackType with syntactic sugar
type StackTypes []StackType

// stackValue is the type for the operand stack.
// Each stackValue is either a valid []byte value or a uint64 value.
// If (.Bytes != nil) the stackValue is a []byte value, otherwise uint64 value.
type stackValue struct {
	Uint  uint64
	Bytes []byte
}

type scratchSpace [256]stackValue

// EvalConstants contains constant parameters that are used by opcodes during evaluation (including both real-execution and simulation).
type EvalConstants struct {
	// MaxLogSize is the limit of total log size from n log calls in a program
	MaxLogSize uint64

	// MaxLogCalls is the limit of total log calls during a program execution
	MaxLogCalls uint64
}

type frame struct {
	retpc  int
	height int

	clear   bool // perform "shift and clear" in retsub
	args    int
	returns int
}

// EvalParams contains data that comes into condition evaluation.
type EvalParams struct {
	// Proto *config.ConsensusParams

	Trace *strings.Builder

	// TxnGroup []transactions.SignedTxnWithAD

	pastScratch []*scratchSpace

	// logger logging.Logger

	// SigLedger LedgerForSignature
	// Ledger    LedgerForLogic

	// optional tracer
	// Tracer EvalTracer

	// MinAvmVersion is the minimum allowed AVM version of this program.
	// The program must reject if its version is less than this version. If
	// MinAvmVersion is nil, we will compute it ourselves
	MinAvmVersion *uint64

	// Amount "overpaid" by the transactions of the group.  Often 0.  When
	// positive, it can be spent by inner transactions.  Shared across a group's
	// txns, so that it can be updated (including upward, by overpaying inner
	// transactions). nil is treated as 0 (used before fee pooling is enabled).
	FeeCredit *uint64

	// Specials *transactions.SpecialAddresses

	// Total pool of app call budget in a group transaction (nil before budget pooling enabled)
	PooledApplicationBudget *int

	// Total allowable inner txns in a group transaction (nil before inner pooling enabled)
	pooledAllowedInners *int

	// available contains resources that may be used even though they are not
	// necessarily directly in the txn's "static arrays". Apps and ASAs go in if
	// the app or asa was created earlier in the txgroup (empty until
	// createdResourcesVersion). Boxes go in when the ep is created, to share
	// availability across all txns in the group.
	// available *resources

	// ioBudget is the number of bytes that the box ref'd boxes can sum to, and
	// the number of bytes that created or written boxes may sum to.
	ioBudget uint64

	// readBudgetChecked allows us to only check the read budget once
	readBudgetChecked bool

	EvalConstants

	// Caching these here means the hashes can be shared across the TxnGroup
	// (and inners, because the cache is shared with the inner EvalParams)
	// appAddrCache map[basics.AppIndex]basics.Address

	// Cache the txid hashing, but do *not* share this into inner EvalParams, as
	// the key is just the index in the txgroup.
	// txidCache      map[int]transactions.Txid
	// innerTxidCache map[int]transactions.Txid

	// The calling context, if this is an inner app call
	caller *EvalContext
}

// EvalContext is the execution context of AVM bytecode.  It contains the full
// state of the running program, and tracks some of the things that the program
// has done, like log messages and inner transactions.
type EvalContext struct {
	*EvalParams

	// determines eval mode: runModeSignature or runModeApplication
	runModeFlags RunMode

	// the index of the transaction being evaluated
	groupIndex int
	// the transaction being evaluated (initialized from groupIndex + ep.TxnGroup)
	// txn *transactions.SignedTxnWithAD

	// Txn.EvalDelta maintains a summary of changes as we go.  We used to
	// compute this from the ledger after a full eval.  But now apps can call
	// apps.  When they do, all of the changes accumulate into the parent's
	// ledger, but Txn.EvalDelta should only have the changes from *this*
	// call. (The changes caused by children are deeper inside - in the
	// EvalDeltas of the InnerTxns inside this EvalDelta) Nice bonus - by
	// keeping the running changes, the debugger can be changed to display them
	// as the app runs.

	stack       []stackValue
	callstack   []frame
	fromCallsub bool

	// appID   basics.AppIndex
	program []byte
	pc      int
	nextpc  int
	intc    []uint64
	bytec   [][]byte
	version uint64
	scratch scratchSpace

	// subtxns []transactions.SignedTxnWithAD // place to build for itxn_submit
	cost    int // cost incurred so far
	logSize int // total log size so far

	// Set of PC values that branches we've seen so far might
	// go. So, if checkStep() skips one, that branch is trying to
	// jump into the middle of a multibyte instruction
	branchTargets []bool

	// Set of PC values that we have begun a checkStep() with. So
	// if a back jump is going to a value that isn't here, it's
	// jumping into the middle of multibyte instruction.
	instructionStarts []bool

	// programHashCached crypto.Digest
}

// NewStackType Initializes a new StackType with fields passed
func NewStackType(at avmType, bounds [2]uint64, stname ...string) StackType {
	name := at.String()

	// It's static, set the name to show
	// the static value
	if bounds[0] == bounds[1] {
		switch at {
		case avmBytes:
			name = fmt.Sprintf("[%d]byte", bounds[0])
		case avmUint64:
			name = fmt.Sprintf("%d", bounds[0])
		}
	}

	if len(stname) > 0 {
		name = stname[0]
	}

	return StackType{Name: name, AVMType: at, Bound: bounds}
}

func (sv stackValue) typeName() string {
	if sv.Bytes != nil {
		return "[]byte"
	}
	return "uint64"
}

func (st StackType) widened() StackType {
	// Take only the avm type
	switch st.AVMType {
	case avmBytes:
		return StackBytes
	case avmUint64:
		return StackUint64
	case avmAny:
		return StackAny
	default:
		panic(fmt.Sprintf("What are you tyring to widen?: %+v", st))
	}
}

// RunMode is a bitset of logic evaluation modes.
// There are currently two such modes: Signature and Application.
type RunMode uint64

func bound(min, max uint64) [2]uint64 {
	return [2]uint64{min, max}
}

func static(size uint64) [2]uint64 {
	return bound(size, size)
}

func (st StackType) String() string {
	return st.Name
}

// Typed tells whether the StackType is a specific concrete type.
func (st StackType) Typed() bool {
	switch st.AVMType {
	case avmUint64, avmBytes:
		return true
	}
	return false
}

func (at avmType) String() string {
	switch at {
	case avmNone:
		return "none"
	case avmAny:
		return "any"
	case avmUint64:
		return "uint64"
	case avmBytes:
		return "[]byte"
	}
	return "internal error, unknown type"
}

const (
	// ModeSig is LogicSig execution
	ModeSig RunMode = 1 << iota

	// ModeApp is application/contract execution
	ModeApp

	// local constant, run in any mode
	modeAny = ModeSig | ModeApp
)

// Any checks if this mode bitset represents any evaluation mode
func (r RunMode) Any() bool {
	return r == modeAny
}

func (r RunMode) String() string {
	switch r {
	case ModeSig:
		return "Signature"
	case ModeApp:
		return "Application"
	case modeAny:
		return "Any"
	default:
	}
	return "Unknown"
}

// maxByteMathSize is the limit of byte strings supplied as input to byte math opcodes
const maxByteMathSize = 64

// maxStringSize is the limit of byte string length in an AVM value
const maxStringSize = 4096

const (
	// avmNone in an OpSpec shows that the op pops or yields nothing
	avmNone avmType = iota

	// avmAny in an OpSpec shows that the op pops or yield any type
	avmAny

	// avmUint64 in an OpSpec shows that the op pops or yields a uint64
	avmUint64

	// avmBytes in an OpSpec shows that the op pops or yields a []byte
	avmBytes
)

var (
	// StackUint64 is any valid uint64
	StackUint64 = NewStackType(avmUint64, bound(0, math.MaxUint64))
	// StackBytes is any valid bytestring
	StackBytes = NewStackType(avmBytes, bound(0, maxStringSize))
	// StackAny could be Bytes or Uint64
	StackAny = StackType{
		Name:    avmAny.String(),
		AVMType: avmAny,
		Bound:   [2]uint64{0, 0},
	}
	// StackNone is used when there is no input or output to
	// an opcode
	StackNone = StackType{
		Name:    avmNone.String(),
		AVMType: avmNone,
	}

	// StackBoolean constrains the int to 1 or 0, representing True or False
	StackBoolean = NewStackType(avmUint64, bound(0, 1), "bool")
	// StackAddress represents an address
	StackAddress = NewStackType(avmBytes, static(32), "address")
	// StackBytes32 represents a bytestring that should have exactly 32 bytes
	StackBytes32 = NewStackType(avmBytes, static(32), "[32]byte")
	// StackBigInt represents a bytestring that should be treated like an int
	StackBigInt = NewStackType(avmBytes, bound(0, maxByteMathSize), "bigint")
	// StackMethodSelector represents a bytestring that should be treated like a method selector
	StackMethodSelector = NewStackType(avmBytes, static(4), "method")
	// StackStateKey represents a bytestring that can be used as a key to some storage (global/local/box)
	StackStateKey = NewStackType(avmBytes, bound(0, 64), "stateKey")
	// StackBoxName represents a bytestring that can be used as a key to a box
	StackBoxName = NewStackType(avmBytes, bound(1, 64), "boxName")

	// StackZeroUint64 is a StackUint64 with a minimum value of 0 and a maximum value of 0
	StackZeroUint64 = NewStackType(avmUint64, bound(0, 0), "0")
	// StackZeroBytes is a StackBytes with a minimum length of 0 and a maximum length of 0
	StackZeroBytes = NewStackType(avmUint64, bound(0, 0), "''")

	// AllStackTypes is a map of all the stack types we recognize
	// so that we can iterate over them in doc prep
	// and use them for opcode proto shorthand
	AllStackTypes = map[rune]StackType{
		'a': StackAny,
		'b': StackBytes,
		'i': StackUint64,
		'x': StackNone,
		'A': StackAddress,
		'I': StackBigInt,
		'T': StackBoolean,
		'H': StackBytes32,
		'M': StackMethodSelector,
		'K': StackStateKey,
		'N': StackBoxName,
	}
)

func parseStackTypes(spec string) StackTypes {
	if spec == "" {
		return nil
	}
	types := make(StackTypes, len(spec))
	for i, letter := range spec {
		st, ok := AllStackTypes[letter]
		if !ok {
			panic(spec)
		}
		types[i] = st
	}
	return types
}

func boolToUint(x bool) uint64 {
	if x {
		return 1
	}
	return 0
}

func boolToSV(x bool) stackValue {
	return stackValue{Uint: boolToUint(x)}
}

// overlaps checks if there is enough overlap
// between the given types that the receiver can
// possible fit in the expected type
func (st StackType) overlaps(expected StackType) bool {
	if st.AVMType == avmNone || expected.AVMType == avmNone {
		return false
	}

	if st.AVMType == avmAny || expected.AVMType == avmAny {
		return true
	}

	// By now, both are either uint or bytes
	// and must match
	if st.AVMType != expected.AVMType {
		return false
	}

	// Same type now
	// Check if our constraints will satisfy the other type
	smin, smax := st.Bound[0], st.Bound[1]
	emin, emax := expected.Bound[0], expected.Bound[1]

	return smin <= emax && smax >= emin
}

func opPlus(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	sum, carry := bits.Add64(cx.stack[prev].Uint, cx.stack[last].Uint, 0)
	if carry > 0 {
		return errors.New("+ overflowed")
	}
	cx.stack[prev].Uint = sum
	cx.stack = cx.stack[:last]
	return nil
}

func opEq(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	ta := cx.stack[prev].avmType()
	tb := cx.stack[last].avmType()
	if ta != tb {
		return fmt.Errorf("cannot compare (%s to %s)", cx.stack[prev].typeName(), cx.stack[last].typeName())
	}
	var cond bool
	if ta == avmBytes {
		cond = bytes.Equal(cx.stack[prev].Bytes, cx.stack[last].Bytes)
	} else {
		cond = cx.stack[prev].Uint == cx.stack[last].Uint
	}
	cx.stack[prev] = boolToSV(cond)
	cx.stack = cx.stack[:last]
	return nil
}

func opReturn(cx *EvalContext) error {
	// Achieve the end condition:
	// Take the last element on the stack and make it the return value (only element on the stack)
	// Move the pc to the end of the program
	last := len(cx.stack) - 1
	cx.stack[0] = cx.stack[last]
	cx.stack = cx.stack[:1]
	cx.nextpc = len(cx.program)
	return nil
}
