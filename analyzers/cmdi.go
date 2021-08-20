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

// CommandInjectionAnalyzer constructs Sinks from a set of functions known to be vulnerable to command injection,
// converts all variables to SSA form to construct a call graph and performs
// recursive taint analysis to search for input sources of user-controllable data
var CommandInjectionAnalyzer = &analysis.Analyzer{
	Name:     "command_injection",
	Doc:      "reports when command injection can occur",
	Run:      cmdInjectionRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

// vulnCmdInjectionFuncs() returns a map of command injection functions that may be vulnerable when used with user controlled input
func vulnCmdInjectionFuncs() map[string][]string {
	return map[string][]string{
		"os/exec": {"Command", "CommandContext"},
	}
}

// command_injection_run runs the command injection analyzer
func cmdInjectionRun(pass *analysis.Pass) (interface{}, error) {
	results := []util.Finding{}

	// Builds SSA model of Go code
	ssaFuncs := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs

	// Creates call graph of function calls
	call_graph := make(util.CallGraph)

	// Fills in call graph
	for _, fn := range ssaFuncs {
		call_graph.AnalyzeFunction(fn)
	}

	// Grabs vulnerable functions to scan for
	vulnPathFuncs := vulnCmdInjectionFuncs()

	// Iterate over every specified vulnerable package
	for pkg, funcs := range vulnPathFuncs {

		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {

			// Construct full name of function
			current_function := pkg + "." + fn

			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range call_graph[current_function] {

				// Check if argument of vulnerable function is tainted by possibly user-controlled input
				taintAnalyzer := util.CreateTaintAnalyzer(pass, vulnFunc.Fn.Pos())
				for i := 0; i < len(vulnFunc.Instr.Call.Args); i++ {
					if taintAnalyzer.ContainsTaint(&vulnFunc.Instr.Call, &vulnFunc.Instr.Call.Args[i], call_graph) {
						message := "Danger: possible command injection detected"
						targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
						taintSource := taintAnalyzer.TaintSource
						finding := util.MakeFinding(message, targetFunc, taintSource, "Command Injection")
						results = append(results, finding)
					}
				}
			}
		}
	}

	return results, nil
}
