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
)

// PathTraversalAnalyzer constructs Sinks from a set of functions known to be vulnerable to path injection
// all variables are converted to SSA form and a call graph is constructed
// recursive taint analysis is then used to search from a given Sink up the callgraph for Sources of user-controllable data
var PathTraversalAnalyzer = &analysis.Analyzer{
	Name:     "path_traversal",
	Doc:      "reports when path traversal can occur",
	Run:      traversalRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

// getVulnerableInjectionFunctions() returns a map of functions that may be vulnerable to path traversal when used with user controlled input
func getVulnInjectionFunctions() map[string][]string {
	return map[string][]string{
		"os":        {"Create", "Open", "OpenFile"},
		"io/ioutil": {"ReadFile", "WriteFile"},
	}
}

// traversalRun runs the path traversal analyzer
func traversalRun(pass *analysis.Pass) (interface{}, error) {

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
	pathFuncs := getVulnInjectionFunctions()

	// Iterate over every specified vulnerable package
	for pkg, funcs := range pathFuncs {

		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {

			// Construct full name of function
			curFunc := pkg + "." + fn

			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range cg[curFunc] {

				// Check if argument of vulnerable function is tainted by possibly user-controlled input
				taintAnalyzer := util.CreateTaintAnalyzer(pass, vulnFunc.Fn.Pos())
				if taintAnalyzer.ContainsTaint(&vulnFunc.Instr.Call, &vulnFunc.Instr.Call.Args[0], cg) {
					message := "Danger: possible path traversal injection detected"

					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					taintSource := taintAnalyzer.TaintSource
					results = append(results, util.MakeFinding(message, targetFunc, taintSource, "CWE-22: Path Traversal"))

				}
			}
		}
	}

	return results, nil
}
