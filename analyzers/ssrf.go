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
	"github.com/praetorian-inc/gokart/util"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// SSRF Analyzer constructs Sinks from a set of functions known to be vulnerable to Server Side Request Forgery,
// converts all variables to SSA form to construct a call graph and performs
// recursive taint analysis to search for input sources of user-controllable data
var SSRFAnalyzer = &analysis.Analyzer{
	Name:     "SSRF",
	Doc:      "reports when SSRF vulnerabilities can occur",
	Run:      ssrfRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

// vulnerable_ssrf_funcs() returns a map of networking functions that may be vulnerable when used with user controlled input
func vulnSsrfFuncs() map[string][]string {
	return map[string][]string{
		"net/http":           {"Do", "Get", "Head", "Post", "PostForm"},
		"(*net/http.Client)": {"Do", "Get", "Head", "Post", "PostForm"},
	}
}

func taintCheck(val *ssa.Value) bool {
	//Alloc of http client
	alloc, ok := (*val).(*ssa.Alloc)
	if ok {
		refs := alloc.Referrers()
		for _, ref := range *refs {
			//fieldAddr of http client
			fieldAddr, ok := (ref).(*ssa.FieldAddr)
			if !ok {
				continue
			}

			//refs to that field
			refs = fieldAddr.Referrers()
			for _, ref := range *refs {
				store, ok := (ref).(*ssa.Store)
				if !ok {
					continue
				}
				makeInterface, ok := store.Val.(*ssa.MakeInterface)
				if !ok {
					continue
				}
				transportAlloc, ok := makeInterface.X.(*ssa.Alloc)
				if !ok {
					continue
				}
				refs = transportAlloc.Referrers()
				for _, ref := range *refs {
					fieldAddr, ok = (ref).(*ssa.FieldAddr)
					if !ok || fieldAddr.Type().String() != "*func(ctx context.Context, network string, addr string) (net.Conn, error)" {
						continue
					}
					//refs to that field
					refs = fieldAddr.Referrers()
					for _, ref := range *refs {
						store, ok = (ref).(*ssa.Store)
						if !ok {
							continue
						}
						closure, ok := store.Val.(*ssa.MakeClosure)
						if !ok {
							continue
						}
						for _, binding := range closure.Bindings {
							transportAlloc, ok := binding.(*ssa.Alloc)
							if !ok {
								continue
							}

							refs = transportAlloc.Referrers()
							for _, ref := range *refs {
								fieldAddr, ok = (ref).(*ssa.FieldAddr)
								if !ok || fieldAddr.Type().String() != "*func(network string, address string, c syscall.RawConn) error" {
									continue
								}
								refs = fieldAddr.Referrers()
								for _, ref := range *refs {
									store, ok = (ref).(*ssa.Store)
									if !ok {
										continue
									}
									if store.Val.String() != "nil:func(network string, address string, c syscall.RawConn) error" {
										return false
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return true
}

// ssrfRun() runs the command injection analyzer
func ssrfRun(pass *analysis.Pass) (interface{}, error) {
	results := []util.Finding{}

	// Builds SSA model of Go code
	ssaFuncs := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs

	// Creates call graph of function calls
	cg := make(util.CallGraph)

	// Fills in call graph
	for _, fn := range ssaFuncs {
		cg.AnalyzeFunction(fn)
	}

	// Grabs vulnerable functions to scan for
	vuln_path_funcs := vulnSsrfFuncs()

	// Iterate over every specified vulnerable package
	for pkg, funcs := range vuln_path_funcs {

		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {

			// Construct full name of function
			curFunc := pkg + "." + fn
			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range cg[curFunc] {
				// Check if argument of vulnerable function is tainted by possibly user-controlled input
				taintAnalyzer := util.CreateTaintAnalyzer(pass, vulnFunc.Fn.Pos())
				//the first arg of any http client calls is the client itself we don't care about checking this for
				//taint since it's not part of the SSRF however, if the control attribute is set on the client then we
				//know it's safe, and we should never mark it as tainted (even if there is a get with user controlled
				//input)
				if pkg == "(*net/http.Client)" {
					if taintCheck(&vulnFunc.Instr.Call.Args[0]) {
						for i := 1; i < len(vulnFunc.Instr.Call.Args); i++ {
							if taintAnalyzer.ContainsTaint(&vulnFunc.Instr.Call, &vulnFunc.Instr.Call.Args[i], cg) {
								message := "Danger: possible SSRF detected"
								targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
								taintSource := taintAnalyzer.TaintSource
								results = append(results, util.MakeFinding(message, targetFunc, taintSource, "SSRF"))

							}
						}
					}
				} else {
					for i := 0; i < len(vulnFunc.Instr.Call.Args); i++ {
						if taintAnalyzer.ContainsTaint(&vulnFunc.Instr.Call, &vulnFunc.Instr.Call.Args[i], cg) {
							message := "Danger: possible SSRF detected"
							targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
							taintSource := taintAnalyzer.TaintSource
							results = append(results, util.MakeFinding(message, targetFunc, taintSource, "SSRF"))

						}
					}
				}
			}
		}
	}

	return results, nil
}
