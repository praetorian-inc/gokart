// Copyright 2021 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package util implements underlying functionality for building and traversing call graphs,
configuraing and building analyzers and generating findings
*/
package util

import (
	"bufio"
	"bytes"
	"fmt"
	"go/token"
	"os"
	"runtime"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"

	"github.com/segmentio/fasthash/fnv1a"
)

type ReturnSet = []ssa.Value

// ReturnValues returns a set of the return values of the function
func ReturnValues(fn *ssa.Function) []ReturnSet {
	res := []ReturnSet{}

	for _, block := range fn.DomPreorder() {
		// a returning block ends in a Return instruction and has no successors
		if len(block.Succs) != 0 {
			continue
		}

		if ret, ok := block.Instrs[len(block.Instrs)-1].(*ssa.Return); ok {
			res = append(res, ret.Results[:])
		}
	}

	return res
}

// CGRelation is a struct that contains information about an instruction and a function in the call graph
type CGRelation struct {
	Instr *ssa.Call
	Fn    *ssa.Function
}
type CallGraph map[string][]CGRelation

// AnalyzeFunction updates the CallGraph to contain relations between callee and caller functions. This should be called once on every function in a local package
func (cg CallGraph) AnalyzeFunction(fn *ssa.Function) {
	for _, block := range fn.DomPreorder() {
		for _, instr := range block.Instrs {
			switch instr := instr.(type) {
			case *ssa.Call:
				if instr.Call.StaticCallee() != nil {
					calleeName := instr.Call.StaticCallee().String()
					// Update the callgraph
					cg[calleeName] = append(cg[calleeName], CGRelation{instr, fn})
				}
			}
		}
	}
}

// ResolveParam returns the caller nodes of a parameter. This is used for tracing parameters back to their source.
func (cg CallGraph) ResolveParam(p *ssa.Parameter) []*ssa.Value {
	// Determine which argument we are in the parent function
	pFunc := p.Parent()
	pIdx := -1
	for i, arg := range pFunc.Params {
		if p.Pos() == arg.Pos() {
			pIdx = i
		}
	}
	// Find all the places the function is called
	callerNodes := make([]*ssa.Value, len(cg[pFunc.String()]))
	for i, rel := range cg[pFunc.String()] {
		callerNodes[i] = &rel.Instr.Call.Args[pIdx]
	}
	return callerNodes
}

// Memoize hashes an ssa.Value and then adds it to the Taint Map while updating the metadata
func (ta TaintAnalyzer) Memoize(val *ssa.Value, vulnerable bool) {
	switch (*val).(type) {
	case *ssa.Phi:
		// Don't want to memoize Phi nodes as recursion will then not check all edges
	default:
		// hash the ssa.Value
		hash := SSAvalToHash(val)
		// get the current map status
		map_status := ta.taint_map[hash]
		// increment the count
		new_count := map_status.Count + 1
		// create the new MapData struct
		mapping := MapData{Mapped: map_status.Mapped, Vulnerable: map_status.Vulnerable, Count: new_count}
		// update the Taint Map
		ta.taint_map[hash] = mapping
	}

}

// SSAvalToHash returns the hash of an ssa.Value to be used in the Taint Map
func SSAvalToHash(val *ssa.Value) uint64 {
	// convert the de-referenced ssa.Value to a byte array
	b_arrayPointer := []byte(fmt.Sprintf("%v", *val))
	// convert the byte array to a string
	val_string := string(b_arrayPointer)
	// if the ssa.Value has a parent, add that to the val_string to be used in the hash. Otherwise just hash the val_string
	if (*val).Parent() != nil {
		b_arrayParent := (*val).Parent().String()
		val_string += b_arrayParent
	}

	// hash the val_string
	hash := fnv1a.HashString64(val_string)
	return hash
}

// GrabSourceCode retrieves the specified line of source code from the specified file
func GrabSourceCode(filename string, lineNumber int) string {

	fileHandle, _ := os.Open(filename)
	defer fileHandle.Close()

	var buff bytes.Buffer
	scanner := bufio.NewScanner(fileHandle)
	scanner.Split(bufio.ScanLines)

	counter := 0

	for scanner.Scan() {
		counter++
		if lineNumber == counter {
			buff.WriteString(scanner.Text())
			break
		}
	}
	return buff.String()
}

// GenerateTaintedCode returns a TaintedCode struct that stores information (source code, filename, linenumber) for a line of code
func GenerateTaintedCode(pass *analysis.Pass, parent *ssa.Function, position token.Pos) TaintedCode {
	vulnerable_code := pass.Fset.Position(position)

	// Evaluate $GOROOT environment variable so correct filepath is generated.
	expanded_filename := os.ExpandEnv(vulnerable_code.Filename)
	if _, err := os.Stat(expanded_filename); os.IsNotExist(err) {
		if strings.Contains(vulnerable_code.Filename, "$GOROOT") {
			vulnerable_code.Filename = strings.Replace(vulnerable_code.Filename, "$GOROOT", runtime.GOROOT(), 1)
		} else {
			vulnerable_code.Filename = "WARNING: Could not find the file at path: " + vulnerable_code.Filename
		}
	} else {
		vulnerable_code.Filename = expanded_filename
	}

	vulnerable_source_code := GrabSourceCode(vulnerable_code.Filename, vulnerable_code.Line)

	var parent_function_name string
	var parent_function_args string
	if parent == nil {
		parent_function_name = "<no parent>"
		parent_function_args = "<no parent - no args>"
	} else {
		parent_function_name = parent.Name()
		parent_function_args = strings.Split(parent.Signature.String(), "func")[1]
	}
	tainted_code := TaintedCode{
		SourceCode:     vulnerable_source_code,
		SourceFilename: vulnerable_code.Filename,
		SourceLineNum:  vulnerable_code.Line,
		ParentFunction: parent_function_name + " " + parent_function_args,
	}
	return tainted_code
}
