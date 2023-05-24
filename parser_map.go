package main

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type lineError struct {
	Line int
	Err  error
}

type intReference struct {
	value uint64

	// position of the opcode start that declares the int value
	position int
}

type byteReference struct {
	value []byte

	// position of the opcode start that declares the byte value
	position int
}

type constReference interface {
	// get the referenced value
	getValue() interface{}

	// check if the referenced value equals other. Other must be the same type
	valueEquals(other interface{}) bool

	// get the index into ops.pending where the opcode for this reference is located
	getPosition() int

	// get the length of the op for this reference in ops.pending
	length(ops *OpStream, assembled []byte) (int, error)

	// create the opcode bytes for a new reference of the same value
	makeNewReference(ops *OpStream, singleton bool, newIndex int) []byte
}

var otherAllowedChars = [256]bool{'+': true, '-': true, '*': true, '/': true, '^': true, '%': true, '&': true, '|': true, '~': true, '!': true, '>': true, '<': true, '=': true, '?': true, '_': true}

// pseudoOps allows us to provide convenient ops that mirror existing ops without taking up another opcode. Using "txn" in version 2 and on, for example, determines whether to actually assemble txn or to use txna instead based on the number of immediates.
// Immediates key of -1 means asmfunc handles number of immediates
// These will then get transferred over into a per-opstream versioned table during assembly
const anyImmediates = -1

// AssemblerDefaultVersion what version of code do we emit by default
// AssemblerDefaultVersion is set to 1 on puprose
// to prevent accidental building of v1 official templates with version 2
// because these templates are not aware of rekeying.
const AssemblerDefaultVersion = 1

// AssemblerMaxVersion is a maximum supported assembler version
const AssemblerMaxVersion = LogicVersion
const assemblerNoVersion = (^uint64(0))

// optimizeConstantsEnabledVersion is the first version of TEAL where the
// assembler optimizes constants introduced by pseudo-ops
const optimizeConstantsEnabledVersion = 4

func asmPushInt(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s needs one immediate argument, was given %d", spec.Name, len(args))
	}
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.errorf(err.Error())
	}
	ops.pending.WriteByte(spec.Opcode)
	var scratch [binary.MaxVarintLen64]byte
	vlen := binary.PutUvarint(scratch[:], val)
	ops.pending.Write(scratch[:vlen])
	return nil
}

func typeEquals(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	top := len(pgm.stack) - 1
	if top >= 0 {
		// Require arg0 and arg1 to have same avm type
		// but the bounds shouldn't matter
		widened := pgm.stack[top].widened()
		return StackTypes{widened, widened}, nil, nil
	}
	return nil, nil, nil
}

// Intc writes opcodes for loading a uint64 constant onto the stack.
func (ops *OpStream) Intc(constIndex uint) {
	switch constIndex {
	case 0:
		ops.pending.WriteByte(OpsByName[ops.Version]["intc_0"].Opcode)
	case 1:
		ops.pending.WriteByte(OpsByName[ops.Version]["intc_1"].Opcode)
	case 2:
		ops.pending.WriteByte(OpsByName[ops.Version]["intc_2"].Opcode)
	case 3:
		ops.pending.WriteByte(OpsByName[ops.Version]["intc_3"].Opcode)
	default:
		if constIndex > 0xff {
			ops.errorf("cannot have more than 256 int constants")
		}
		ops.pending.WriteByte(OpsByName[ops.Version]["intc"].Opcode)
		ops.pending.WriteByte(uint8(constIndex))
	}
	if constIndex >= uint(len(ops.intc)) {
		ops.errorf("intc %d is not defined", constIndex)
	} else {
		ops.trace("intc %d: %d", constIndex, ops.intc[constIndex])
	}
}

// IntLiteral writes opcodes for loading a uint literal
func (ops *OpStream) IntLiteral(val uint64) {
	ops.hasPseudoInt = true

	found := false
	var constIndex uint
	for i, cv := range ops.intc {
		if cv == val {
			constIndex = uint(i)
			found = true
			break
		}
	}

	if !found {
		if ops.cntIntcBlock > 0 {
			ops.errorf("int %d used without %d in intcblock", val, val)
		}
		constIndex = uint(len(ops.intc))
		ops.intc = append(ops.intc, val)
	}
	ops.intcRefs = append(ops.intcRefs, intReference{
		value:    val,
		position: ops.pending.Len(),
	})
	ops.Intc(constIndex)
}

func (ops *OpStream) trace(format string, args ...interface{}) {
	if ops.Trace == nil {
		return
	}
	fmt.Fprintf(ops.Trace, format, args...)
}

// func (ops *OpStream) lineError(line int, problem interface{}) error {
// 	var err lineError
// 	switch p := problem.(type) {
// 	case string:
// 		err = lineError{Line: line, Err: errors.New(p)}
// 	case error:
// 		err = lineError{Line: line, Err: p}
// 	default:
// 		err = lineError{Line: line, Err: fmt.Errorf("%#v", p)}
// 	}
// 	ops.Errors = append(ops.Errors, err)
// 	return err
// }

// func (ops *OpStream) error(problem interface{}) error {
// 	return ops.lineError(ops.sourceLine, problem)
// }

func asmInt(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s needs one immediate argument, was given %d", spec.Name, len(args))
	}

	// After backBranchEnabledVersion, control flow is confusing, so if there's
	// a manual cblock, use push instead of trying to use what's given.
	if ops.cntIntcBlock > 0 && ops.Version >= backBranchEnabledVersion {
		// We don't understand control-flow, so use pushint
		//ops.warnf("int %s used with explicit intcblock. must pushint", args[0])
		pushint := OpsByName[ops.Version]["pushint"]
		return asmPushInt(ops, &pushint, args)
	}

	// There are no backjumps, but there are multiple cblocks. Maybe one is
	// conditional skipped. Too confusing.
	if ops.cntIntcBlock > 1 {
		pushint, ok := OpsByName[ops.Version]["pushint"]
		if ok {
			return asmPushInt(ops, &pushint, args)
		}
		return ops.errorf("int %s used with manual intcblocks. Use intc.", args[0])
	}

	// In both of the above clauses, we _could_ track whether a particular
	// intcblock dominates the current instruction. If so, we could use it.

	// check txn type constants
	i, ok := txnTypeMap[args[0]]
	if ok {
		ops.IntLiteral(i)
		return nil
	}
	// check OnCompletion constants
	oc, isOCStr := onCompletionMap[args[0]]
	if isOCStr {
		ops.IntLiteral(oc)
		return nil
	}
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.errorf(err.Error())
	}
	ops.IntLiteral(val)
	return nil
}

func typePushInt(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	types := make(StackTypes, len(args))
	for i := range types {
		val, err := strconv.ParseUint(args[i], 10, 64)
		if err != nil {
			types[i] = StackUint64
		} else {
			types[i] = NewStackType(avmUint64, bound(val, val))
		}
	}
	return nil, types, nil
}

func base32DecodeAnyPadding(x string) (val []byte, err error) {
	val, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(x)
	if err != nil {
		// try again with standard padding
		var e2 error
		val, e2 = base32.StdEncoding.DecodeString(x)
		if e2 == nil {
			err = nil
		}
	}
	return
}

func parseStringLiteral(input string) (result []byte, err error) {
	start := 0
	end := len(input) - 1
	if input[start] != '"' || input[end] != '"' {
		return nil, fmt.Errorf("no quotes")
	}
	start++

	escapeSeq := false
	hexSeq := false
	result = make([]byte, 0, end-start+1)

	// skip first and last quotes
	pos := start
	for pos < end {
		char := input[pos]
		if char == '\\' && !escapeSeq {
			if hexSeq {
				return nil, fmt.Errorf("escape seq inside hex number")
			}
			escapeSeq = true
			pos++
			continue
		}
		if escapeSeq {
			escapeSeq = false
			switch char {
			case 'n':
				char = '\n'
			case 'r':
				char = '\r'
			case 't':
				char = '\t'
			case '\\':
				char = '\\'
			case '"':
				char = '"'
			case 'x':
				hexSeq = true
				pos++
				continue
			default:
				return nil, fmt.Errorf("invalid escape seq \\%c", char)
			}
		}
		if hexSeq {
			hexSeq = false
			if pos >= len(input)-2 { // count a closing quote
				return nil, fmt.Errorf("non-terminated hex seq")
			}
			num, err := strconv.ParseUint(input[pos:pos+2], 16, 8)
			if err != nil {
				return nil, err
			}
			char = uint8(num)
			pos++
		}

		result = append(result, char)
		pos++
	}
	if escapeSeq || hexSeq {
		return nil, fmt.Errorf("non-terminated escape seq")
	}

	return
}

func parseBinaryArgs(args []string) (val []byte, consumed int, err error) {
	arg := args[0]
	if strings.HasPrefix(arg, "base32(") || strings.HasPrefix(arg, "b32(") {
		open := strings.IndexRune(arg, '(')
		close := strings.IndexRune(arg, ')')
		if close == -1 {
			err = errors.New("byte base32 arg lacks close paren")
			return
		}
		val, err = base32DecodeAnyPadding(arg[open+1 : close])
		if err != nil {
			return
		}
		consumed = 1
	} else if strings.HasPrefix(arg, "base64(") || strings.HasPrefix(arg, "b64(") {
		open := strings.IndexRune(arg, '(')
		close := strings.IndexRune(arg, ')')
		if close == -1 {
			err = errors.New("byte base64 arg lacks close paren")
			return
		}
		val, err = base64.StdEncoding.DecodeString(arg[open+1 : close])
		if err != nil {
			return
		}
		consumed = 1
	} else if strings.HasPrefix(arg, "0x") {
		val, err = hex.DecodeString(arg[2:])
		if err != nil {
			return
		}
		consumed = 1
	} else if arg == "base32" || arg == "b32" {
		if len(args) < 2 {
			err = fmt.Errorf("need literal after 'byte %s'", arg)
			return
		}
		val, err = base32DecodeAnyPadding(args[1])
		if err != nil {
			return
		}
		consumed = 2
	} else if arg == "base64" || arg == "b64" {
		if len(args) < 2 {
			err = fmt.Errorf("need literal after 'byte %s'", arg)
			return
		}
		val, err = base64.StdEncoding.DecodeString(args[1])
		if err != nil {
			return
		}
		consumed = 2
	} else if len(arg) > 1 && arg[0] == '"' && arg[len(arg)-1] == '"' {
		val, err = parseStringLiteral(arg)
		consumed = 1
	} else {
		err = fmt.Errorf("byte arg did not parse: %v", arg)
		return
	}
	return
}

func asmPushBytes(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 0 {
		return ops.errorf("%s needs byte literal argument", spec.Name)
	}
	val, consumed, err := parseBinaryArgs(args)
	if err != nil {
		return ops.errorf(err.Error())
	}
	if len(args) != consumed {
		return ops.errorf("%s with extraneous argument", spec.Name)
	}
	ops.pending.WriteByte(spec.Opcode)
	var scratch [binary.MaxVarintLen64]byte
	vlen := binary.PutUvarint(scratch[:], uint64(len(val)))
	ops.pending.Write(scratch[:vlen])
	ops.pending.Write(val)
	return nil
}

// Bytec writes opcodes for loading a []byte constant onto the stack.
func (ops *OpStream) Bytec(constIndex uint) {
	switch constIndex {
	case 0:
		ops.pending.WriteByte(OpsByName[ops.Version]["bytec_0"].Opcode)
	case 1:
		ops.pending.WriteByte(OpsByName[ops.Version]["bytec_1"].Opcode)
	case 2:
		ops.pending.WriteByte(OpsByName[ops.Version]["bytec_2"].Opcode)
	case 3:
		ops.pending.WriteByte(OpsByName[ops.Version]["bytec_3"].Opcode)
	default:
		if constIndex > 0xff {
			ops.errorf("cannot have more than 256 byte constants")
		}
		ops.pending.WriteByte(OpsByName[ops.Version]["bytec"].Opcode)
		ops.pending.WriteByte(uint8(constIndex))
	}
	if constIndex >= uint(len(ops.bytec)) {
		ops.errorf("bytec %d is not defined", constIndex)
	} else {
		ops.trace("bytec %d %s", constIndex, hex.EncodeToString(ops.bytec[constIndex]))
	}
}

// ByteLiteral writes opcodes and data for loading a []byte literal
// Values are accumulated so that they can be put into a bytecblock
func (ops *OpStream) ByteLiteral(val []byte) {
	ops.hasPseudoByte = true

	found := false
	var constIndex uint
	for i, cv := range ops.bytec {
		if bytes.Equal(cv, val) {
			found = true
			constIndex = uint(i)
			break
		}
	}
	if !found {
		if ops.cntBytecBlock > 0 {
			ops.errorf("byte/addr/method used without value in bytecblock")
		}
		constIndex = uint(len(ops.bytec))
		ops.bytec = append(ops.bytec, val)
	}
	ops.bytecRefs = append(ops.bytecRefs, byteReference{
		value:    val,
		position: ops.pending.Len(),
	})
	ops.Bytec(constIndex)
}

func (ops *OpStream) cycle(macro string, previous ...string) bool {
	replacement, ok := ops.macros[macro]
	if !ok {
		return false
	}
	if len(previous) > 0 && macro == previous[0] {
		ops.errorf("Macro cycle discovered: %s", strings.Join(append(previous, macro), " -> "))
		return true
	}
	for _, token := range replacement {
		if ops.cycle(token, append(previous, macro)...) {
			return true
		}
	}
	return false
}

// recheckMacroNames goes through previously defined macros and ensures they
// don't use opcodes/fields from newly obtained version. Therefore it repeats
// some checks that don't need to be repeated, in the interest of simplicity.
func (ops *OpStream) recheckMacroNames() error {
	errored := false
	for macroName := range ops.macros {
		err := checkMacroName(macroName, ops.Version, ops.labels)
		if err != nil {
			delete(ops.macros, macroName)
			ops.errorf(err.Error())
			errored = true
		}
	}
	if errored {
		return errors.New("version is incompatible with defined macros")
	}
	return nil
}

// optimizeConstants optimizes a given constant block and the ops that reference
// it to reduce code size. This is achieved by ordering the constant block from
// most frequently referenced constants to least frequently referenced, since
// the first 4 constant can use a special opcode to save space. Additionally,
// any constants with a reference of 1 are taken out of the constant block and
// instead referenced with an immediate op.
func (ops *OpStream) optimizeConstants(refs []constReference, constBlock []interface{}) (optimizedConstBlock []interface{}, err error) {
	type constFrequency struct {
		value interface{}
		freq  int
	}

	freqs := make([]constFrequency, len(constBlock))

	for i, value := range constBlock {
		freqs[i].value = value
	}

	for _, ref := range refs {
		found := false
		for i := range freqs {
			if ref.valueEquals(freqs[i].value) {
				freqs[i].freq++
				found = true
				break
			}
		}
		if !found {
			err = ops.lineErrorf(ops.OffsetToLine[ref.getPosition()], "Value not found in constant block: %v", ref.getValue())
			return
		}
	}

	for _, f := range freqs {
		if f.freq == 0 {
			err = ops.errorf("Member of constant block is not used: %v", f.value)
			return
		}
	}

	// sort values by greatest to smallest frequency
	// since we're using a stable sort, constants with the same frequency
	// will retain their current ordering (i.e. first referenced, first in constant block)
	sort.SliceStable(freqs, func(i, j int) bool {
		return freqs[i].freq > freqs[j].freq
	})

	// sort refs from last to first
	// this way when we iterate through them and potentially change the size of the assembled
	// program, the later positions will not affect the indexes of the earlier positions
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].getPosition() > refs[j].getPosition()
	})

	raw := ops.pending.Bytes()
	for _, ref := range refs {
		singleton := false
		newIndex := -1
		for i, f := range freqs {
			if ref.valueEquals(f.value) {
				singleton = f.freq == 1
				newIndex = i
				break
			}
		}
		if newIndex == -1 {
			return nil, ops.lineErrorf(ops.OffsetToLine[ref.getPosition()], "Value not found in constant block: %v", ref.getValue())
		}

		newBytes := ref.makeNewReference(ops, singleton, newIndex)
		var currentBytesLen int
		currentBytesLen, err = ref.length(ops, raw)
		if err != nil {
			return
		}

		positionDelta := len(newBytes) - currentBytesLen
		position := ref.getPosition()
		raw = replaceBytes(raw, position, currentBytesLen, newBytes)

		// update all indexes into ops.pending that have been shifted by the above line

		// This is a huge optimization for long repetitive programs. Takes
		// BenchmarkUintMath from 160sec to 19s.
		if positionDelta == 0 {
			continue
		}

		for i := range ops.intcRefs {
			if ops.intcRefs[i].position > position {
				ops.intcRefs[i].position += positionDelta
			}
		}

		for i := range ops.bytecRefs {
			if ops.bytecRefs[i].position > position {
				ops.bytecRefs[i].position += positionDelta
			}
		}

		for label := range ops.labels {
			if ops.labels[label] > position {
				ops.labels[label] += positionDelta
			}
		}

		for i := range ops.labelReferences {
			if ops.labelReferences[i].position > position {
				ops.labelReferences[i].position += positionDelta
				ops.labelReferences[i].offsetPosition += positionDelta
			}
		}

		fixedOffsetsToLine := make(map[int]int, len(ops.OffsetToLine))
		for pos, sourceLine := range ops.OffsetToLine {
			if pos > position {
				fixedOffsetsToLine[pos+positionDelta] = sourceLine
			} else {
				fixedOffsetsToLine[pos] = sourceLine
			}
		}
		ops.OffsetToLine = fixedOffsetsToLine
	}

	ops.pending = *bytes.NewBuffer(raw)

	optimizedConstBlock = make([]interface{}, 0)
	for _, f := range freqs {
		if f.freq == 1 {
			break
		}
		optimizedConstBlock = append(optimizedConstBlock, f.value)
	}

	return
}

func (ref intReference) getValue() interface{} {
	return ref.value
}

func (ref intReference) valueEquals(other interface{}) bool {
	return ref.value == other.(uint64)
}

func (ref intReference) getPosition() int {
	return ref.position
}

func (ref intReference) length(ops *OpStream, assembled []byte) (int, error) {
	opIntc0 := OpsByName[ops.Version]["intc_0"].Opcode
	opIntc1 := OpsByName[ops.Version]["intc_1"].Opcode
	opIntc2 := OpsByName[ops.Version]["intc_2"].Opcode
	opIntc3 := OpsByName[ops.Version]["intc_3"].Opcode
	opIntc := OpsByName[ops.Version]["intc"].Opcode

	switch assembled[ref.position] {
	case opIntc0, opIntc1, opIntc2, opIntc3:
		return 1, nil
	case opIntc:
		return 2, nil
	default:
		return 0, ops.lineErrorf(ops.OffsetToLine[ref.position], "Unexpected op at intReference: %d", assembled[ref.position])
	}
}

func (ref intReference) makeNewReference(ops *OpStream, singleton bool, newIndex int) []byte {
	opIntc0 := OpsByName[ops.Version]["intc_0"].Opcode
	opIntc1 := OpsByName[ops.Version]["intc_1"].Opcode
	opIntc2 := OpsByName[ops.Version]["intc_2"].Opcode
	opIntc3 := OpsByName[ops.Version]["intc_3"].Opcode
	opIntc := OpsByName[ops.Version]["intc"].Opcode
	opPushInt := OpsByName[ops.Version]["pushint"].Opcode

	if singleton {
		var scratch [binary.MaxVarintLen64]byte
		vlen := binary.PutUvarint(scratch[:], ref.value)

		newBytes := make([]byte, 1+vlen)
		newBytes[0] = opPushInt
		copy(newBytes[1:], scratch[:vlen])

		return newBytes
	}

	switch newIndex {
	case 0:
		return []byte{opIntc0}
	case 1:
		return []byte{opIntc1}
	case 2:
		return []byte{opIntc2}
	case 3:
		return []byte{opIntc3}
	default:
		return []byte{opIntc, uint8(newIndex)}
	}
}

func (ref byteReference) getPosition() int {
	return ref.position
}

func (ref byteReference) getValue() interface{} {
	return ref.value
}

func (ref byteReference) valueEquals(other interface{}) bool {
	return bytes.Equal(ref.value, other.([]byte))
}

func (ref byteReference) length(ops *OpStream, assembled []byte) (int, error) {
	opBytec0 := OpsByName[ops.Version]["bytec_0"].Opcode
	opBytec1 := OpsByName[ops.Version]["bytec_1"].Opcode
	opBytec2 := OpsByName[ops.Version]["bytec_2"].Opcode
	opBytec3 := OpsByName[ops.Version]["bytec_3"].Opcode
	opBytec := OpsByName[ops.Version]["bytec"].Opcode

	switch assembled[ref.position] {
	case opBytec0, opBytec1, opBytec2, opBytec3:
		return 1, nil
	case opBytec:
		return 2, nil
	default:
		return 0, ops.lineErrorf(ops.OffsetToLine[ref.position], "Unexpected op at byteReference: %d", assembled[ref.position])
	}
}

func (ref byteReference) makeNewReference(ops *OpStream, singleton bool, newIndex int) []byte {
	opBytec0 := OpsByName[ops.Version]["bytec_0"].Opcode
	opBytec1 := OpsByName[ops.Version]["bytec_1"].Opcode
	opBytec2 := OpsByName[ops.Version]["bytec_2"].Opcode
	opBytec3 := OpsByName[ops.Version]["bytec_3"].Opcode
	opBytec := OpsByName[ops.Version]["bytec"].Opcode
	opPushBytes := OpsByName[ops.Version]["pushbytes"].Opcode

	if singleton {
		var scratch [binary.MaxVarintLen64]byte
		vlen := binary.PutUvarint(scratch[:], uint64(len(ref.value)))

		newBytes := make([]byte, 1+vlen+len(ref.value))
		newBytes[0] = opPushBytes
		copy(newBytes[1:], scratch[:vlen])
		copy(newBytes[1+vlen:], ref.value)

		return newBytes
	}

	switch newIndex {
	case 0:
		return []byte{opBytec0}
	case 1:
		return []byte{opBytec1}
	case 2:
		return []byte{opBytec2}
	case 3:
		return []byte{opBytec3}
	default:
		return []byte{opBytec, uint8(newIndex)}
	}
}

// optimizeIntcBlock rewrites the existing intcblock and the ops that reference
// it to reduce code size. This is achieved by ordering the intcblock from most
// frequently referenced constants to least frequently referenced, since the
// first 4 constant can use the intc_X ops to save space. Additionally, any
// ints with a reference of 1 are taken out of the intcblock and instead created
// with the pushint op.
//
// This function only optimizes constants introduces by the int pseudo-op, not
// preexisting intcblocks in the code.
func (ops *OpStream) optimizeIntcBlock() error {
	if ops.cntIntcBlock > 0 {
		// don't optimize an existing intcblock, only int pseudo-ops
		return nil
	}

	constBlock := make([]interface{}, len(ops.intc))
	for i, value := range ops.intc {
		constBlock[i] = value
	}

	constRefs := make([]constReference, len(ops.intcRefs))
	for i, ref := range ops.intcRefs {
		constRefs[i] = ref
	}

	// remove all intcRefs here so that optimizeConstants does not alter them
	// when it fixes indexes into ops.pending
	ops.intcRefs = nil

	optimizedIntc, err := ops.optimizeConstants(constRefs, constBlock)

	if err != nil {
		return err
	}

	ops.intc = make([]uint64, len(optimizedIntc))
	for i, value := range optimizedIntc {
		ops.intc[i] = value.(uint64)
	}

	return nil
}

// optimizeBytecBlock rewrites the existing bytecblock and the ops that
// reference it to reduce code size. This is achieved by ordering the bytecblock
// from most frequently referenced constants to least frequently referenced,
// since the first 4 constant can use the bytec_X ops to save space.
// Additionally, any bytes with a reference of 1 are taken out of the bytecblock
// and instead created with the pushbytes op.
//
// This function only optimizes constants introduces by the byte or addr
// pseudo-ops, not preexisting bytecblocks in the code.
func (ops *OpStream) optimizeBytecBlock() error {
	if ops.cntBytecBlock > 0 {
		// don't optimize an existing bytecblock, only byte/addr pseudo-ops
		return nil
	}

	constBlock := make([]interface{}, len(ops.bytec))
	for i, value := range ops.bytec {
		constBlock[i] = value
	}

	constRefs := make([]constReference, len(ops.bytecRefs))
	for i, ref := range ops.bytecRefs {
		constRefs[i] = ref
	}

	// remove all bytecRefs here so that optimizeConstants does not alter them
	// when it fixes indexes into ops.pending
	ops.bytecRefs = nil

	optimizedBytec, err := ops.optimizeConstants(constRefs, constBlock)

	if err != nil {
		return err
	}

	ops.bytec = make([][]byte, len(optimizedBytec))
	for i, value := range optimizedBytec {
		ops.bytec[i] = value.([]byte)
	}

	return nil
}

// returns allows opcodes like `txn` to be specific about their return value
// types, based on the field requested, rather than use Any as specified by
// opSpec. It replaces StackAny in the top `count` elements of the typestack.
func (ops *OpStream) returns(spec *OpSpec, replacement StackType) {
	if ops.known.deadcode {
		return
	}
	end := len(ops.known.stack)
	tip := ops.known.stack[end-len(spec.Return.Types):]
	for i := range tip {
		if tip[i].AVMType == avmAny {
			tip[i] = replacement
			return
		}
	}
	// returns was called on an OpSpec with no StackAny in its Returns
	panic(fmt.Sprintf("%+v", spec))
}

// byte {base64,b64,base32,b32}(...)
// byte {base64,b64,base32,b32} ...
// byte 0x....
// byte "this is a string\n"
func asmByte(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 0 {
		return ops.errorf("%s needs byte literal argument", spec.Name)
	}

	// After backBranchEnabledVersion, control flow is confusing, so if there's
	// a manual cblock, use push instead of trying to use what's given.
	if ops.cntBytecBlock > 0 && ops.Version >= backBranchEnabledVersion {
		// We don't understand control-flow, so use pushbytes
		ops.errorf("byte %s used with explicit bytecblock. must pushbytes", args[0])
		pushbytes := OpsByName[ops.Version]["pushbytes"]
		return asmPushBytes(ops, &pushbytes, args)
	}

	// There are no backjumps, but there are multiple cblocks. Maybe one is
	// conditional skipped. Too confusing.
	if ops.cntBytecBlock > 1 {
		pushbytes, ok := OpsByName[ops.Version]["pushbytes"]
		if ok {
			return asmPushBytes(ops, &pushbytes, args)
		}
		return ops.errorf("byte %s used with manual bytecblocks. Use bytec.", args[0])
	}

	// In both of the above clauses, we _could_ track whether a particular
	// bytecblock dominates the current instruction. If so, we could use it.

	val, consumed, err := parseBinaryArgs(args)
	if err != nil {
		return ops.errorf(err.Error())
	}
	if len(args) != consumed {
		return ops.errorf("%s with extraneous argument", spec.Name)
	}
	ops.ByteLiteral(val)
	return nil
}

// reset clears existing knowledge and permissively allows any stack value.  It's intended to be invoked after encountering a label or pragma type tracking change.
func (pgm *ProgramKnowledge) reset() {
	pgm.stack = nil
	pgm.bottom = StackAny
	pgm.fp = -1
	pgm.deadcode = false
	for i := range pgm.scratchSpace {
		pgm.scratchSpace[i] = StackAny
	}
}

func (pgm *ProgramKnowledge) deaden() {
	pgm.stack = pgm.stack[:0]
	pgm.deadcode = true
}

func typeByte(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	if len(args) == 0 {
		return nil, StackTypes{StackBytes}, nil
	}
	val, _, _ := parseBinaryArgs(args)
	l := uint64(len(val))
	return nil, StackTypes{NewStackType(avmBytes, static(l), fmt.Sprintf("[%d]byte", l))}, nil
}

// addr A1EU...
// parses base32-with-checksum account address strings into a byte literal
func asmAddr(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s needs one immediate argument, was given %d", spec.Name, len(args))
	}
	//addr, err := basics.UnmarshalChecksumAddress(args[0])
	//var addr string
	var err error
	if err != nil {
		return ops.errorf(err.Error())
	}
	//ops.ByteLiteral(addr[:])
	return nil
}

// method "add(uint64,uint64)uint64"
func asmMethod(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 0 {
		return ops.errorf("method requires a literal argument")
	}
	arg := args[0]
	if len(arg) > 1 && arg[0] == '"' && arg[len(arg)-1] == '"' {
		methodSig, err := parseStringLiteral(arg)
		if err != nil {
			return ops.errorf(err.Error())
		}
		//methodSigStr := string(methodSig)
		//err = abi.VerifyMethodSignature(methodSigStr)
		err = nil
		if err != nil {
			// Warn if an invalid signature is used. Don't return an error, since the ABI is not
			// governed by the core protocol, so there may be changes to it that we don't know about
			ops.errorf("Invalid ARC-4 ABI method signature for method op: %s", err.Error())
		}
		hash := sha512.Sum512_256(methodSig)
		ops.ByteLiteral(hash[0:4])
		return nil
	}
	return ops.errorf("Unable to parse method signature")
}

var pseudoOps = map[string]map[int]OpSpec{
	"int":  {anyImmediates: OpSpec{Name: "int", Proto: proto(":i"), OpDetails: assembler(asmInt).typed(typePushInt)}},
	"byte": {anyImmediates: OpSpec{Name: "byte", Proto: proto(":b"), OpDetails: assembler(asmByte).typed(typeByte)}},
	// parse basics.Address, actually just another []byte constant
	"addr": {anyImmediates: OpSpec{Name: "addr", Proto: proto(":b"), OpDetails: assembler(asmAddr)}},
	// take a signature, hash it, and take first 4 bytes, actually just another []byte constant
	"method":  {anyImmediates: OpSpec{Name: "method", Proto: proto(":b"), OpDetails: assembler(asmMethod)}},
	"txn":     {1: OpSpec{Name: "txn"}, 2: OpSpec{Name: "txna"}},
	"gtxn":    {2: OpSpec{Name: "gtxn"}, 3: OpSpec{Name: "gtxna"}},
	"gtxns":   {1: OpSpec{Name: "gtxns"}, 2: OpSpec{Name: "gtxnsa"}},
	"extract": {0: OpSpec{Name: "extract3"}, 2: OpSpec{Name: "extract"}},
	"replace": {0: OpSpec{Name: "replace3"}, 1: OpSpec{Name: "replace2"}},
}

type asmFunc func(*OpStream, *OpSpec, []string) error
type refineFunc func(pgm *ProgramKnowledge, immediates []string) (StackTypes, StackTypes, error)
type errorfFunc func(s string, a ...interface{}) error

// ProgramKnowledge tracks statically known information as we assemble
type ProgramKnowledge struct {
	// list of the types known to be on the value stack, based on specs of
	// opcodes seen while assembling. In normal code, the tip of the stack must
	// match the next opcode's Arg.Types, and is then replaced with its
	// Return.Types. If `deadcode` is true, `stack` should be empty.
	stack StackTypes

	// bottom is the type given out when `stack` is empty. It is StackNone at
	// program start, so, for example, a `+` opcode at the start of a program
	// fails. But when a label or callsub is encountered, `stack` is truncated
	// and `bottom` becomes StackAny, because we don't track program state
	// coming in from elsewhere. A `+` after a label succeeds, because the stack
	// "vitually" contains an infinite list of StackAny.
	bottom StackType

	// deadcode indicates that the program is in deadcode, so no type checking
	// errors should be reported.
	deadcode bool

	// fp is the frame pointer, if known/usable, or -1 if not.  When
	// encountering a `proto`, `stack` is grown to fit `args`, and this `fp` is
	// set to the top of those args.  This may not be the "real" fp when the
	// program is actually evaluated, but it is good enough for frame_{dig/bury}
	// to work from there.
	fp int

	scratchSpace [256]StackType
}

type labelReference struct {
	sourceLine int

	// position of the label reference
	position int

	label string

	// ending positions of the opcode containing the label reference.
	offsetPosition int
}

func errorf(s string, a ...interface{}) {
	fmt.Println(s)
}

// OpStream is destination for program and scratch space
type OpStream struct {
	Version  uint64
	Trace    *strings.Builder
	Warnings []error     // informational warnings, shouldn't stop assembly
	Errors   []lineError // errors that should prevent final assembly
	Program  []byte      // Final program bytes. Will stay nil if any errors

	// Running bytes as they are assembled. jumps must be resolved
	// and cblocks added before these bytes become a legal program.
	pending bytes.Buffer

	intc         []uint64       // observed ints in code. We'll put them into a intcblock
	intcRefs     []intReference // references to int pseudo-op constants, used for optimization
	cntIntcBlock int            // prevent prepending intcblock because asm has one
	hasPseudoInt bool           // were any `int` pseudo ops used?

	bytec         [][]byte        // observed bytes in code. We'll put them into a bytecblock
	bytecRefs     []byteReference // references to byte/addr pseudo-op constants, used for optimization
	cntBytecBlock int             // prevent prepending bytecblock because asm has one
	hasPseudoByte bool            // were any `byte` (or equivalent) pseudo ops used?

	// tracks information we know to be true at the point being assembled
	known        ProgramKnowledge
	typeTracking bool

	// current sourceLine during assembly
	sourceLine int

	// map label string to position within pending buffer
	labels map[string]int

	// track references in order to patch in jump offsets
	labelReferences []labelReference

	// map opcode offsets to source line
	OffsetToLine map[int]int

	HasStatefulOps bool

	// Need new copy for each opstream
	versionedPseudoOps map[string]map[int]OpSpec

	macros map[string][]string

	errorf errorfFunc
}

func byteImm(value string, label string) (byte, error) {
	res, err := strconv.ParseUint(value, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("unable to parse %s %#v as integer", label, value)
	}
	if res > 255 {
		return 0, fmt.Errorf("%s beyond 255: %d", label, res)
	}
	return byte(res), err
}

func joinIntsOnOr(singularTerminator string, list ...int) string {
	if len(list) == 1 {
		switch list[0] {
		case 0:
			return "no " + singularTerminator + "s"
		case 1:
			return "1 " + singularTerminator
		default:
			return fmt.Sprintf("%d %ss", list[0], singularTerminator)
		}
	}
	sort.Ints(list)
	errMsg := ""
	for i, val := range list {
		if i+1 < len(list) {
			errMsg += fmt.Sprintf("%d or ", val)
		} else {
			errMsg += fmt.Sprintf("%d ", val)
		}
	}
	return errMsg + singularTerminator + "s"
}

func int8Imm(value string, label string) (byte, error) {
	res, err := strconv.ParseInt(value, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("unable to parse %s %#v as int8", label, value)
	}
	return byte(res), err
}

// replaceBytes returns a slice that is the same as s, except the range starting
// at index with length originalLen is replaced by newBytes. The returned slice
// may be the same as s, or it may be a new slice
func replaceBytes(s []byte, index, originalLen int, newBytes []byte) []byte {
	prefix := s[:index]
	suffix := s[index+originalLen:]

	// if we can fit the new bytes into the existing slice, no need to create a
	// new one
	if len(newBytes) <= originalLen {
		copy(s[index:], newBytes)
		copy(s[index+len(newBytes):], suffix)
		return s[:len(s)+len(newBytes)-originalLen]
	}

	replaced := make([]byte, len(prefix)+len(newBytes)+len(suffix))
	copy(replaced, prefix)
	copy(replaced[index:], newBytes)
	copy(replaced[index+len(newBytes):], suffix)

	return replaced
}

// Basic assembly. Any extra bytes of opcode are encoded as byte immediates.
func asmDefault(ops *OpStream, spec *OpSpec, args []string) error {
	expected := len(spec.OpDetails.Immediates)
	if len(args) != expected {
		if expected == 1 {
			return ops.errorf("%s expects 1 immediate argument", spec.Name)
		}
		return ops.errorf("%s expects %d immediate arguments", spec.Name, expected)
	}
	ops.pending.WriteByte(spec.Opcode)
	for i, imm := range spec.OpDetails.Immediates {
		var correctImmediates []string
		var numImmediatesWithField []int
		pseudos, isPseudoName := ops.versionedPseudoOps[spec.Name]
		switch imm.kind {
		case immByte:
			if imm.Group != nil {
				fs, ok := imm.Group.SpecByName(args[i])
				if !ok {
					_, err := byteImm(args[i], "")
					if err == nil {
						// User supplied a uint, so we see if any of the other immediates take uints
						for j, otherImm := range spec.OpDetails.Immediates {
							if otherImm.kind == immByte && otherImm.Group == nil {
								correctImmediates = append(correctImmediates, strconv.Itoa(j+1))
							}
						}
						if len(correctImmediates) > 0 {
							errMsg := spec.Name
							if isPseudoName {
								errMsg += " with " + joinIntsOnOr("immediate", len(args))
							}
							return ops.errorf("%s can only use %#v as immediate %s", errMsg, args[i], strings.Join(correctImmediates, " or "))
						}
					}
					if isPseudoName {
						for numImms, ps := range pseudos {
							for _, psImm := range ps.OpDetails.Immediates {
								if psImm.kind == immByte && psImm.Group != nil {
									if _, ok := psImm.Group.SpecByName(args[i]); ok {
										numImmediatesWithField = append(numImmediatesWithField, numImms)
									}
								}
							}
						}
						if len(numImmediatesWithField) > 0 {
							return ops.errorf("%#v field of %s can only be used with %s", args[i], spec.Name, joinIntsOnOr("immediate", numImmediatesWithField...))
						}
					}
					return ops.errorf("%s unknown field: %#v", spec.Name, args[i])
				}
				// refine the typestack now, so it is maintained even if there's a version error
				if fs.Type().Typed() {
					ops.returns(spec, fs.Type())
				}
				if fs.Version() > ops.Version {
					return ops.errorf("%s %s field was introduced in v%d. Missed #pragma version?",
						spec.Name, args[i], fs.Version())
				}
				ops.pending.WriteByte(fs.Field())
			} else {
				// simple immediate that must be a number from 0-255
				val, err := byteImm(args[i], imm.Name)
				if err != nil {
					if strings.Contains(err.Error(), "unable to parse") {
						// Perhaps the field works in a different order
						for j, otherImm := range spec.OpDetails.Immediates {
							if otherImm.kind == immByte && otherImm.Group != nil {
								if _, match := otherImm.Group.SpecByName(args[i]); match {
									correctImmediates = append(correctImmediates, strconv.Itoa(j+1))
								}
							}
						}
						if len(correctImmediates) > 0 {
							errMsg := spec.Name
							if isPseudoName {
								errMsg += " with " + joinIntsOnOr("immediate", len(args))
							}
							return ops.errorf("%s can only use %#v as immediate %s", errMsg, args[i], strings.Join(correctImmediates, " or "))
						}
					}
					return ops.errorf("%s %w", spec.Name, err)
				}
				ops.pending.WriteByte(val)
			}
		case immInt8:
			val, err := int8Imm(args[i], imm.Name)
			if err != nil {
				return ops.errorf("%s %w", spec.Name, err)
			}
			ops.pending.WriteByte(val)
		default:
			return ops.errorf("unable to assemble immKind %d", imm.kind)
		}
	}
	return nil
}

// label resets knowledge to reflect that control may enter from elsewhere.
func (pgm *ProgramKnowledge) label() {
	if pgm.deadcode {
		pgm.reset()
	}
}

func (pgm *ProgramKnowledge) pop() StackType {
	if len(pgm.stack) == 0 {
		return pgm.bottom
	}
	last := len(pgm.stack) - 1
	t := pgm.stack[last]
	pgm.stack = pgm.stack[:last]
	return t
}

func (pgm *ProgramKnowledge) push(types ...StackType) {
	pgm.stack = append(pgm.stack, types...)
}

// createLabel inserts a label to point to the next instruction, reporting an
// error for a duplicate.
func (ops *OpStream) createLabel(label string) {
	if _, ok := ops.labels[label]; ok {
		ops.errorf("duplicate label %#v", label)
	}
	ops.labels[label] = ops.pending.Len()
	ops.known.label()
}

func checkMacroName(macroName string, version uint64, labels map[string]int) error {
	var firstRune rune
	var secondRune rune
	count := 0
	for _, r := range macroName {
		if count == 0 {
			firstRune = r
		} else if count == 1 {
			secondRune = r
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !otherAllowedChars[r] {
			return fmt.Errorf("%s character not allowed in macro name", string(r))
		}
		count++
	}
	if unicode.IsDigit(firstRune) {
		return fmt.Errorf("Cannot begin macro name with number: %s", macroName)
	}
	if len(macroName) > 1 && (firstRune == '-' || firstRune == '+') {
		if unicode.IsDigit(secondRune) {
			return fmt.Errorf("Cannot begin macro name with number: %s", macroName)
		}
	}
	// Note parentheses are not allowed characters, so we don't have to check for b64(AAA) syntax
	if macroName == "b64" || macroName == "base64" {
		return fmt.Errorf("Cannot use %s as macro name", macroName)
	}
	if macroName == "b32" || macroName == "base32" {
		return fmt.Errorf("Cannot use %s as macro name", macroName)
	}
	_, isTxnType := txnTypeMap[macroName]
	_, isOnCompletion := onCompletionMap[macroName]
	if isTxnType || isOnCompletion {
		return fmt.Errorf("Named constants cannot be used as macro names: %s", macroName)
	}
	if _, ok := pseudoOps[macroName]; ok {
		return fmt.Errorf("Macro names cannot be pseudo-ops: %s", macroName)
	}
	if version != assemblerNoVersion {
		if _, ok := OpsByName[version][macroName]; ok {
			return fmt.Errorf("Macro names cannot be opcodes: %s", macroName)
		}
		if fieldNames[version][macroName] {
			return fmt.Errorf("Macro names cannot be field names: %s", macroName)
		}
	}
	if _, ok := labels[macroName]; ok {
		return fmt.Errorf("Labels cannot be used as macro names: %s", macroName)
	}
	return nil
}

func define(ops *OpStream, tokens []string) error {
	if tokens[0] != "#define" {
		return ops.errorf("invalid syntax: %s", tokens[0])
	}
	if len(tokens) < 3 {
		return ops.errorf("define directive requires a name and body")
	}
	name := tokens[1]
	err := checkMacroName(name, ops.Version, ops.labels)
	if err != nil {
		return ops.errorf(err.Error())
	}
	saved, ok := ops.macros[name]
	ops.macros[name] = tokens[2:len(tokens):len(tokens)]
	if ops.cycle(tokens[1]) {
		if ok {
			ops.macros[tokens[1]] = saved
		} else {
			delete(ops.macros, tokens[1])
		}
	}
	return nil
}

func pragma(ops *OpStream, tokens []string) error {
	if tokens[0] != "#pragma" {
		return ops.errorf("invalid syntax: %s", tokens[0])
	}
	if len(tokens) < 2 {
		return ops.errorf("empty pragma")
	}
	key := tokens[1]
	switch key {
	case "version":
		if len(tokens) < 3 {
			return ops.errorf("no version value")
		}
		if len(tokens) > 3 {
			return ops.errorf("unexpected extra tokens: %s", strings.Join(tokens[3:], " "))
		}
		value := tokens[2]
		var ver uint64
		if ops.pending.Len() > 0 {
			return ops.errorf("#pragma version is only allowed before instructions")
		}
		ver, err := strconv.ParseUint(value, 0, 64)
		if err != nil {
			return ops.errorf("bad #pragma version: %#v", value)
		}
		if ver > AssemblerMaxVersion {
			return ops.errorf("unsupported version: %d", ver)
		}

		// We initialize Version with assemblerNoVersion as a marker for
		// non-specified version because version 0 is valid
		// version for v1.
		if ops.Version == assemblerNoVersion {
			ops.Version = ver
			return ops.recheckMacroNames()
		}
		if ops.Version != ver {
			return ops.errorf("version mismatch: assembling v%d with v%d assembler", ver, ops.Version)
		}
		// ops.Version is already correct, or needed to be upped.
		return nil
	case "typetrack":
		if len(tokens) < 3 {
			return ops.errorf("no typetrack value")
		}
		if len(tokens) > 3 {
			return ops.errorf("unexpected extra tokens: %s", strings.Join(tokens[3:], " "))
		}
		value := tokens[2]
		on, err := strconv.ParseBool(value)
		if err != nil {
			return ops.errorf("bad #pragma typetrack: %#v", value)
		}
		prev := ops.typeTracking
		if !prev && on {
			ops.known.reset()
		}
		ops.typeTracking = on

		return nil
	default:
		return ops.errorf("unsupported pragma directive: %#v", key)
	}
}

// newline not included since handled in scanner
var tokenSeparators = [256]bool{'\t': true, ' ': true, ';': true}

func tokensFromLine(line string) []string {
	var tokens []string

	i := 0
	for i < len(line) && tokenSeparators[line[i]] {
		if line[i] == ';' {
			tokens = append(tokens, ";")
		}
		i++
	}
	start := i
	inString := false // tracked to allow spaces and comments inside
	inBase64 := false // tracked to allow '//' inside
	for i < len(line) {
		if !tokenSeparators[line[i]] { // if not space
			switch line[i] {
			case '"': // is a string literal?
				if !inString {
					if i == 0 || i > 0 && tokenSeparators[line[i-1]] {
						inString = true
					}
				} else {
					if line[i-1] != '\\' { // if not escape symbol
						inString = false
					}
				}
			case '/': // is a comment?
				if i < len(line)-1 && line[i+1] == '/' && !inBase64 && !inString {
					if start != i { // if a comment without whitespace
						tokens = append(tokens, line[start:i])
					}
					return tokens
				}
			case '(': // is base64( seq?
				prefix := line[start:i]
				if prefix == "base64" || prefix == "b64" {
					inBase64 = true
				}
			case ')': // is ) as base64( completion
				if inBase64 {
					inBase64 = false
				}
			default:
			}
			i++
			continue
		}

		// we've hit a space, end last token unless inString

		if !inString {
			token := line[start:i]
			tokens = append(tokens, token)
			if line[i] == ';' {
				tokens = append(tokens, ";")
			}
			if inBase64 {
				inBase64 = false
			} else if token == "base64" || token == "b64" {
				inBase64 = true
			}
		}
		i++

		// gobble up consecutive whitespace (but notice semis)
		if !inString {
			for i < len(line) && tokenSeparators[line[i]] {
				if line[i] == ';' {
					tokens = append(tokens, ";")
				}
				i++
			}
			start = i
		}
	}

	// add rest of the string if any
	if start < len(line) {
		tokens = append(tokens, line[start:i])
	}
	return tokens

}

type directiveFunc func(*OpStream, []string) error

var directives = map[string]directiveFunc{"pragma": pragma, "define": define}

// newOpStream constructs OpStream instances ready to invoke assemble. A new
// OpStream must be used for each call to assemble().
func newOpStream(version uint64) OpStream {
	o := OpStream{
		labels:       make(map[string]int),
		OffsetToLine: make(map[int]int),
		typeTracking: true,
		Version:      version,
		macros:       make(map[string][]string),
		known:        ProgramKnowledge{fp: -1},
	}

	for i := range o.known.scratchSpace {
		o.known.scratchSpace[i] = StackZeroUint64
	}

	return o
}

// nextStatement breaks tokens into two slices at the first semicolon and expands macros along the way.
func nextStatement(ops *OpStream, tokens []string) (current, rest []string) {
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		replacement, ok := ops.macros[token]
		if ok {
			tokens = append(tokens[0:i], append(replacement, tokens[i+1:]...)...)
			// backup to handle potential re-expansion of the first token in the expansion
			i--
			continue
		}
		if token == ";" {
			return tokens[:i], tokens[i+1:]
		}
	}
	return tokens, nil
}

// Differentiates between specs in pseudoOps that can be assembled on their own and those that need to grab a different spec
func isFullSpec(spec OpSpec) bool {
	return spec.asm != nil
}

func prepareVersionedPseudoTable(version uint64) map[string]map[int]OpSpec {
	m := make(map[string]map[int]OpSpec)
	for name, specs := range pseudoOps {
		m[name] = make(map[int]OpSpec)
		for numImmediates, spec := range specs {
			if isFullSpec(spec) {
				m[name][numImmediates] = spec
				continue
			}
			newSpec, ok := OpsByName[version][spec.Name]
			if ok {
				m[name][numImmediates] = newSpec
			} else {
				m[name][numImmediates] = OpsByName[AssemblerMaxVersion][spec.Name]
			}
		}
	}
	return m
}

func pseudoImmediatesError(ops *OpStream, name string, specs map[int]OpSpec) {
	immediateCounts := make([]int, len(specs))
	i := 0
	for numImms := range specs {
		immediateCounts[i] = numImms
		i++
	}
	ops.errorf(name + " expects " + joinIntsOnOr("immediate argument", immediateCounts...))
}

// mergeProtos allows us to support typetracking of pseudo-ops which are given an improper number of immediates
// by creating a new proto that is a combination of all the pseudo-op's possibilities
func mergeProtos(specs map[int]OpSpec) (Proto, uint64, bool) {
	var args StackTypes
	var returns StackTypes
	var minVersion uint64
	i := 0
	for _, spec := range specs {
		if i == 0 {
			args = spec.Arg.Types
			returns = spec.Return.Types
			minVersion = spec.Version
		} else {
			if spec.Version < minVersion {
				minVersion = spec.Version
			}
			if len(args) != len(spec.Arg.Types) || len(returns) != len(spec.Return.Types) {
				return Proto{}, 0, false
			}
			for j := range args {
				if args[j] != spec.Arg.Types[j] {
					args[j] = StackAny
				}
			}
			for j := range returns {
				if returns[j] != spec.Return.Types[j] {
					returns[j] = StackAny
				}
			}
		}
		i++
	}
	return Proto{typedList{args, ""}, typedList{returns, ""}}, minVersion, true
}

// unknownOpcodeComplaint returns the best error it can for a missing opcode,
// plus a "standin" OpSpec, if possible.
func unknownOpcodeComplaint(name string, v uint64) (OpSpec, error) {
	first, last := -1, -1
	var standin OpSpec
	for i := 1; i < len(OpsByName); i++ {
		spec, ok := OpsByName[i][name]
		if ok {
			standin = spec
			if first == -1 {
				first = i
			}
			last = i
		}
	}
	if first > int(v) {
		return standin, fmt.Errorf("%s opcode was introduced in v%d", name, first)
	}
	if last != -1 && last < int(v) {
		return standin, fmt.Errorf("%s opcode was removed in v%d", name, last+1)
	}
	return OpSpec{}, fmt.Errorf("unknown opcode: %s", name)
}

// getSpec finds the OpSpec we need during assembly based on its name, our current version, and the immediates passed in
// Note getSpec handles both normal OpSpecs and those supplied by versionedPseudoOps
// The returned string is the spec's name, annotated if it was a pseudoOp with no immediates to help disambiguate typetracking errors
func getSpec(ops *OpStream, name string, args []string) (OpSpec, string, bool) {
	pseudoSpecs, ok := ops.versionedPseudoOps[name]
	if ok {
		pseudo, ok := pseudoSpecs[len(args)]
		if !ok {
			// Could be that pseudoOp wants to handle immediates itself so check -1 key
			pseudo, ok = pseudoSpecs[anyImmediates]
			if !ok {
				// Number of immediates supplied did not match any of the pseudoOps of the given name, so we try to construct a mock spec that can be used to track types
				pseudoImmediatesError(ops, name, pseudoSpecs)
				proto, version, ok := mergeProtos(pseudoSpecs)
				if !ok {
					return OpSpec{}, "", false
				}
				pseudo = OpSpec{Name: name, Proto: proto, Version: version, OpDetails: OpDetails{asm: func(*OpStream, *OpSpec, []string) error { return nil }}}
			}
		}
		pseudo.Name = name
		if pseudo.Version > ops.Version {
			ops.errorf("%s opcode with %s was introduced in v%d", pseudo.Name, joinIntsOnOr("immediate", len(args)), pseudo.Version)
		}
		if len(args) == 0 {
			return pseudo, pseudo.Name + " without immediates", true
		}
		return pseudo, pseudo.Name, true
	}
	fmt.Println("mmm", ops.Version, name)
	spec, ok := OpsByName[ops.Version][name]
	if !ok {
		var err error
		spec, err = unknownOpcodeComplaint(name, ops.Version)
		// unknownOpcodeComplaint's job is to return a nice error, so err != nil
		ops.errorf(err.Error())
	}
	return spec, spec.Name, ok
}

// recordSourceLine adds an entry to pc to line mapping
func (ops *OpStream) recordSourceLine() {
	ops.OffsetToLine[ops.pending.Len()] = ops.sourceLine - 1
}

func (ops *OpStream) lineError(line int, problem interface{}) error {
	var err lineError
	switch p := problem.(type) {
	case string:
		err = lineError{Line: line, Err: errors.New(p)}
	case error:
		err = lineError{Line: line, Err: p}
	default:
		err = lineError{Line: line, Err: fmt.Errorf("%#v", p)}
	}
	ops.Errors = append(ops.Errors, err)
	return err.Err
}

func (ops *OpStream) lineErrorf(line int, format string, a ...interface{}) error {
	return ops.lineError(line, fmt.Errorf(format, a...))
}

func (ops *OpStream) typeErrorf(format string, args ...interface{}) {
	if ops.typeTracking {
		ops.errorf(format, args...)
	}
}

// prependCBlocks completes the assembly by inserting cblocks if needed.
func (ops *OpStream) prependCBlocks() []byte {
	var scratch [binary.MaxVarintLen64]byte
	prebytes := bytes.Buffer{}
	vlen := binary.PutUvarint(scratch[:], ops.Version)
	prebytes.Write(scratch[:vlen])
	if len(ops.intc) > 0 && ops.cntIntcBlock == 0 {
		prebytes.WriteByte(OpsByName[ops.Version]["intcblock"].Opcode)
		vlen := binary.PutUvarint(scratch[:], uint64(len(ops.intc)))
		prebytes.Write(scratch[:vlen])
		for _, iv := range ops.intc {
			vlen = binary.PutUvarint(scratch[:], iv)
			prebytes.Write(scratch[:vlen])
		}
	}
	if len(ops.bytec) > 0 && ops.cntBytecBlock == 0 {
		prebytes.WriteByte(OpsByName[ops.Version]["bytecblock"].Opcode)
		vlen := binary.PutUvarint(scratch[:], uint64(len(ops.bytec)))
		prebytes.Write(scratch[:vlen])
		for _, bv := range ops.bytec {
			vlen = binary.PutUvarint(scratch[:], uint64(len(bv)))
			prebytes.Write(scratch[:vlen])
			prebytes.Write(bv)
		}
	}

	pbl := prebytes.Len()
	outl := ops.pending.Len()
	out := make([]byte, pbl+outl)
	pl, err := prebytes.Read(out)
	if pl != pbl || err != nil {
		ops.errorf("wat: %d prebytes, %d to buffer? err=%w", pbl, pl, err)
		return nil
	}
	ol, err := ops.pending.Read(out[pl:])
	if ol != outl || err != nil {
		ops.errorf("%d program bytes but %d to buffer. err=%w", outl, ol, err)
		return nil
	}

	// fixup offset to line mapping
	newOffsetToLine := make(map[int]int, len(ops.OffsetToLine))
	for o, l := range ops.OffsetToLine {
		newOffsetToLine[o+pbl] = l
	}
	ops.OffsetToLine = newOffsetToLine

	return out
}

func (ops *OpStream) resolveLabels() {
	saved := ops.sourceLine
	raw := ops.pending.Bytes()
	reported := make(map[string]bool)
	for _, lr := range ops.labelReferences {
		ops.sourceLine = lr.sourceLine // so errors get reported where the label was used
		dest, ok := ops.labels[lr.label]
		if !ok {
			if !reported[lr.label] {
				ops.errorf("reference to undefined label %#v", lr.label)
			}
			reported[lr.label] = true
			continue
		}

		// All branch targets are encoded as 2 offset bytes. The destination is relative to the end of the
		// instruction they appear in, which is available in lr.offsetPostion
		if ops.Version < backBranchEnabledVersion && dest < lr.offsetPosition {
			ops.errorf("label %#v is a back reference, back jump support was introduced in v4", lr.label)
			continue
		}
		jump := dest - lr.offsetPosition
		if jump > 0x7fff {
			ops.errorf("label %#v is too far away", lr.label)
			continue
		}
		raw[lr.position] = uint8(jump >> 8)
		raw[lr.position+1] = uint8(jump & 0x0ff)
	}
	ops.pending = *bytes.NewBuffer(raw)
	ops.sourceLine = saved
}

// trackStack checks that the typeStack has `args` on it, then pushes `returns` to it.
func (ops *OpStream) trackStack(args StackTypes, returns StackTypes, instruction []string) {
	// If in deadcode, allow anything. Maybe it's some sort of onchain data.
	if ops.known.deadcode {
		return
	}
	argcount := len(args)
	if argcount > len(ops.known.stack) && ops.known.bottom.AVMType == avmNone {
		ops.typeErrorf("%s expects %d stack arguments but stack height is %d",
			strings.Join(instruction, " "), argcount, len(ops.known.stack))
	} else {
		firstPop := true
		for i := argcount - 1; i >= 0; i-- {
			argType := args[i]
			stype := ops.known.pop()
			if firstPop {
				firstPop = false
				ops.trace("pops(%s", argType)
			} else {
				ops.trace(", %s", argType)
			}
			if !stype.overlaps(argType) {
				ops.typeErrorf("%s arg %d wanted type %s got %s",
					strings.Join(instruction, " "), i, argType, stype)
			}
		}
		if !firstPop {
			ops.trace(")")
		}
	}

	if len(returns) > 0 {
		ops.known.push(returns...)
		ops.trace(" pushes(%s", returns[0])
		if len(returns) > 1 {
			for _, rt := range returns[1:] {
				ops.trace(", %s", rt)
			}
		}
		ops.trace(")")
	}
}

var varIndex = 1
var stack []int

var viperCodeGen = map[string]func(args []string) string{
    "int": func(args []string) string {
        varIndex++
        stack = append(stack, varIndex)
        return fmt.Sprintf("var var%d: Int := %s", varIndex, args[0])
    },
    "+": func(args []string) string {
        varIndex++
        var1, var2 := stack[len(stack)-2], stack[len(stack)-1]
        stack = stack[:len(stack)-2]
        stack = append(stack, varIndex)
        return fmt.Sprintf("var var%d: Int := var%d + var%d", varIndex, var1, var2)
    },
    "==": func(args []string) string {
        varIndex++
        var1, var2 := stack[len(stack)-2], stack[len(stack)-1]
        stack = stack[:len(stack)-2]
        stack = append(stack, varIndex)
        return fmt.Sprintf("var var%d: Bool := var%d == var%d", varIndex, var1, var2)
    },
}

func (ops *OpStream) toViper(text string, methodName string) {
    if strings.TrimSpace(text) == "" {
        fmt.Println("Cannot generate Viper codes from empty program text")
        return
    }

    fin := strings.NewReader(text)
    scanner := bufio.NewScanner(fin)

    varIndex := 1
    stack := []int{}
	var returnType string

	opcodeResultType := map[string]string{
		"int":  "Int",
		"+":    "Int",
		"==":   "Bool",
	}

    viperCodeGen := map[string]func(args []string) string{
        "int": func(args []string) string {
            stack = append(stack, varIndex)
            defer func() { varIndex++ }()
            return fmt.Sprintf("var var%d: Int := %s", varIndex, args[0])
        },
        "+": func(args []string) string {
            var1, var2 := stack[len(stack)-2], stack[len(stack)-1]
            stack = stack[:len(stack)-2]
            stack = append(stack, varIndex)
            defer func() { varIndex++ }()
            return fmt.Sprintf("var var%d: Int := var%d + var%d", varIndex, var1, var2)
        },
        "==": func(args []string) string {
            var1, var2 := stack[len(stack)-2], stack[len(stack)-1]
            stack = stack[:len(stack)-2]
            stack = append(stack, varIndex)
            defer func() { varIndex++ }()
            return fmt.Sprintf("var var%d: Bool := var%d == var%d", varIndex, var1, var2)
        },
		"return": func(args []string) string {
			return fmt.Sprintf("$result := var%d", varIndex-1)
		},
    }

	viperBody := ""

    //viperCode := fmt.Sprintf("method %s() returns ($result: Bool)\n{\n", methodName)

    for scanner.Scan() {
        line := scanner.Text()
        tokens := strings.Fields(line)

        if len(tokens) == 0 {
            continue
        }

        if viperFunc, ok := viperCodeGen[tokens[0]]; ok {
			viperBody += "  " + viperFunc(tokens[1:]) + "\n"
			returnType = opcodeResultType[tokens[0]]
		} else {
			fmt.Printf("Unsupported opcode: %s\n", tokens[0])
		}
    }

    //viperCode += fmt.Sprintf("  $result := var%d\n}\n", varIndex-1)
	viperCode := fmt.Sprintf("method %s() returns ($result: %s)\n{\n", methodName, returnType) + viperBody
	viperCode += "}\n"

    if err := scanner.Err(); err != nil {
        if errors.Is(err, bufio.ErrTooLong) {
            err = errors.New("line too long")
        }
        fmt.Println(err.Error())
    }

    // Create a new .vpr file with the methodName as the file name
	file, err := os.Create(fmt.Sprintf("%s.vpr", methodName))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer file.Close()

	// Write the Viper code to the file
	_, err = file.WriteString(viperCode)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func main() {
	source := `
	int 2
	int 1
	+
	int 2
	==
	return
	`

	fmt.Println("Source TEAL code:")
	fmt.Println(source)
	var ver uint64 = uint64(1)
	ops := newOpStream(ver)
	ops.toViper(source, "func1")
}
