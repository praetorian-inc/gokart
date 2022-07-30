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

package analyzers

import (
	"fmt"
	"go/constant"
	"go/token"

	"github.com/praetorian-inc/gokart/util"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// RSAKeyLenAnalyzer is used to resolve constant values used for RSA key generation in order to more accurately
// detect use of an insecure RSA key length constructed
// all variables are converted to SSA form and a call graph is constructed
// recursive analysis is then used to resolve variables used as a key length to a final constant value at the callsite
var RsaKeylenAnalyzer = &analysis.Analyzer{
	Name:       "rsa_keylen",
	Doc:        "reports when rsa keys are too short",
	Run:        rsaRun,
	Requires:   []*analysis.Analyzer{buildssa.Analyzer},
	ResultType: resultType,
}

const RECOMMENDED_KEYLEN = 2048

// vulnerableRsaFuncs() returns a map of functions that generate RSA keys
func vulnerableRsaFuncs() map[string][]string {
	return map[string][]string{
		"crypto/rsa": {"GenerateKey"},
	}
}

// EvalConst attempts to take a value, and simplify it down to a single constant
// it returns a tuple of (the constant, whether or not it successfully simplified)
func EvalConst(expr ssa.Value, cg util.CallGraph) (*ssa.Const, bool) {

	switch expr := expr.(type) {

	case *ssa.Const:
		return expr, true
	case *ssa.BinOp:
		X, okX := EvalConst(expr.X, cg)
		Y, okY := EvalConst(expr.Y, cg)

		if okX && okY {
			return merge(X, Y, expr)
		}
	case *ssa.Call:
		if dest := expr.Common().StaticCallee(); dest != nil {
			rets := util.ReturnValues(dest)
			if len(rets) == 1 && len(rets[0]) == 1 {
				return EvalConst(rets[0][0], cg)
			}
		}
	case *ssa.Parameter:
		var values []*ssa.Value
		values = cg.ResolveParam(expr)
		return EvalConst(*values[0], cg)

	case *ssa.Phi:
		var res bool
		var val *ssa.Const
		val, res = EvalConst(expr.Edges[0], cg)

		for _, edge := range expr.Edges {
			var tmp *ssa.Const
			var tmp2 bool
			tmp, tmp2 = EvalConst(edge, cg)
			if tmp.Int64() < val.Int64() {
				val = tmp //val ends up being the shortest value that this phi node could be
			}
			res = res && tmp2 //res is whether or not the boolean expr could be evaluated
		}
		return val, res
	}

	return nil, false
}

// Merge merges two Consts to a BinOp
func merge(x, y *ssa.Const, op *ssa.BinOp) (*ssa.Const, bool) {
	switch op.Op {
	case token.ADD, token.SUB, token.MUL:
		return ssa.NewConst(constant.BinaryOp(x.Value, op.Op, y.Value), x.Type()), true
	case token.QUO:
		return ssa.NewConst(constant.BinaryOp(x.Value, token.QUO_ASSIGN, y.Value), x.Type()), true

	}
	return nil, false
}

// keylen_check recursively checks if a vulnerable function that relies on RSA is using a number of bits that is less than RECOMMENDED_KEYLEN
func keylen_check(pass *analysis.Pass, keylen ssa.Value, cg util.CallGraph) bool {
	unsafe := false

	switch keylen := keylen.(type) {
	case *ssa.Const:
		real_len := keylen.Int64()
		if real_len < RECOMMENDED_KEYLEN {
			unsafe = true
		}
	case *ssa.Phi:
		for _, edge := range keylen.Edges {
			if keylen != edge {
				unsafe = unsafe || keylen_check(pass, edge, cg)
			}
		}
	case *ssa.BinOp:
		if val, ok := EvalConst(keylen, cg); ok {
			unsafe = keylen_check(pass, val, cg)
		}
	case *ssa.Call:
		if dest := keylen.Common().StaticCallee(); dest != nil {
			returns := util.ReturnValues(dest)
			for _, retval := range returns {
				unsafe = unsafe || keylen_check(pass, retval[0], cg)
			}
		}
	case *ssa.Parameter:
		var values []*ssa.Value
		values = cg.ResolveParam(keylen)
		if len(values) > 0 {
			unsafe = unsafe || keylen_check(pass, *values[0], cg)
		}
	}
	return unsafe
}

// rsaRun runs the rsa keylength analyzer
func rsaRun(pass *analysis.Pass) (interface{}, error) {
	results := []util.Finding{}
	// Builds SSA model of Go code
	ssa_functions := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs

	// Creates call graph of function calls
	call_graph := make(util.CallGraph)

	// Fills in call graph
	for _, fn := range ssa_functions {
		call_graph.AnalyzeFunction(fn)
	}

	// Grabs vulnerable functions to scan for
	vuln_rsa_funcs := vulnerableRsaFuncs()

	// Iterate over every specified vulnerable package
	for pkg, funcs := range vuln_rsa_funcs {

		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {

			// Construct full name of function
			current_function := pkg + "." + fn

			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range call_graph[current_function] {

				// Check if argument of vulnerable function has keylen that is less than RECOMMENDED_KEYLEN
				if keylen_check(pass, vulnFunc.Instr.Call.Args[1], call_graph) {
					message := fmt.Sprintf("Danger: RSA key length is too short, recommend %d", RECOMMENDED_KEYLEN)
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					results = append(results, util.MakeFinding(message, targetFunc, nil, "CWE-326: Inadequate Encryption Strength"))
				}
			}
		}
	}

	return results, nil
}
