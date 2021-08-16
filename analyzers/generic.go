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
	"io/ioutil"
	"log"

	"github.com/praetorian-inc/gokart/util"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"gopkg.in/yaml.v3"
)

// Creates generic taint analyzer based on Sources and Sinks defined in analyzers.yaml file
func genericFunctionRun(pass *analysis.Pass, vulnPathFuncs map[string][]string,
	name string, message string) (interface{}, error) {
	results := []util.Finding{}

	// Build SSA model of Go code
	ssaFuncs := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs

	// Create call graph of function calls
	cg := make(util.CallGraph)

	// Fill in call graph
	for _, fn := range ssaFuncs {
		cg.AnalyzeFunction(fn)
	}

	// Iterate over every specified vulnerable package
	for pkg, funcs := range vulnPathFuncs {
		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {
			// Construct full name of function
			currentFunc := pkg + "." + fn
			// Iterate over occurences of vulnerable function in call graph
			for _, vulnFunc := range cg[currentFunc] {
				// Check if argument of vulnerable function is tainted by possibly user-controlled input
				taintAnalyzer := util.CreateTaintAnalyzer(pass, vulnFunc.Fn.Pos())
				for i := 0; i < len(vulnFunc.Instr.Call.Args); i++ {
					if taintAnalyzer.ContainsTaint(&vulnFunc.Instr.Call, &vulnFunc.Instr.Call.Args[i], cg) {
						targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
						taintSource := taintAnalyzer.TaintSource
						results = append(results, util.MakeFinding(message, targetFunc, taintSource, name))
					}
				}
			}
		}
	}
	return results, nil
}

// LoadGenericAnalyzers creates generic taint anlalyzers from custom Sources and Sinks defined in analyzers.yaml
// converts all variables to SSA form to construct a call graph and performs
// recursive taint analysis to search for input sources of user-controllable data

func LoadGenericAnalyzers(yaml_path string) []*analysis.Analyzer {
	yfile, err := ioutil.ReadFile(yaml_path)
	if err != nil {
		log.Fatal(err)
	}

	data := make(map[interface{}]map[interface{}]map[interface{}]interface{})
	err = yaml.Unmarshal(yfile, &data)
	if err != nil {
		log.Fatal(err)
	}

	// Load analyzers from the interface
	analyzers := []*analysis.Analyzer{}
	m := data["analyzers"]
	for analyzerName, analyzerDict := range m {
		// Get the vulnerability message
		message := ""
		if analyzerDict["message"] != nil {
			message = analyzerDict["message"].(string)
		}

		// Load the map of vulnerable functions
		vulnCalls := make(map[string][]string)
		yamlCallsMap := analyzerDict["vuln_calls"].(map[string]interface{})
		for pkgName, packageVulnFuncs := range yamlCallsMap {
			var newList []string
			vulnCalls[pkgName] = newList
			packageVulnFuncsList := packageVulnFuncs.([]interface{})
			for _, val := range packageVulnFuncsList {
				vulnCalls[pkgName] = append(vulnCalls[pkgName], val.(string))
			}
		}

		// Wrap generic_function_run with a function that the analyze package can use
		analyzerFunc := func(pass *analysis.Pass) (interface{}, error) {
			return genericFunctionRun(pass, vulnCalls, analyzerName.(string), message)
		}

		// Form the analyzer object and append to the analyzer list
		analysisRun := new(analysis.Analyzer)
		analysisRun.Name = "path_traversal"
		analysisRun.Doc = analyzerDict["doc"].(string)
		analysisRun.Run = analyzerFunc
		analysisRun.Requires = []*analysis.Analyzer{buildssa.Analyzer}
		analyzers = append(analyzers, analysisRun)
	}

	return analyzers
}
