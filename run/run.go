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
Package run controls the loading of go code and the running of analyzers.
*/
package run

import (
	"fmt"
	"go/token"
	"os"
	"strings"

	"github.com/praetorian-inc/gokart/util"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/packages"
)

// Load go packages and run the analyzers on them. Returns a list of findings
func Run(analyzers []*analysis.Analyzer, packages ...string) ([]util.Finding, bool, error) {

	pkgs, success, err := LoadPackages(packages...)
	if err != nil {
		return nil, false, err
	}

	results := []util.Finding{}
	for _, pkg := range pkgs {
		result, err := RunAnalyzers(analyzers, pkg)
		if err != nil {
			return nil, false, err
		}
		results = append(results, result...)
	}

	return results, success, nil

}

// Load go packages
func LoadPackages(packagesList ...string) ([]*packages.Package, bool, error) {
	success := true
	conf := packages.Config{
		Mode: packages.LoadSyntax,
		//Disable loading tests. If we enable this, then packages will be loaded twice. Once with tests, once without.
		//This causes us to report findings twice, even if there are no tests in the package
		Tests: false,
	}

	//Load all packages that have been configured to be scanned, watch out for memory errors
	pkgs, err := packages.Load(&conf, packagesList...)

	if err != nil {
		return nil, false, err
	}
	// Detect any packages that are unable to be scanned due to compilation or accessibility errors
	badpkgs := make(map[*packages.Package]bool)
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		if len(pkg.Errors) != 0 {
			badpkgs[pkg] = true
		}
	})

	if len(badpkgs) != 0 {
		fmt.Fprintf(os.Stderr, "\nUh oh, a dashboard light is on! GoKart was unable to load the following packages: \n")
		pkgs = RemoveBadPackages(pkgs, badpkgs)
		fmt.Fprintf(os.Stderr, "\n\n")
	}

	// Print error message if no scannable packages are found
	if len(pkgs) == 0 {
		fmt.Fprintf(os.Stderr, "CRASH! GoKart didn't find any files to scan! Make sure the usage is correct to get GoKart back on track. \n"+
			"If the usage appears to be correct, try pointing gokart at the directory from where you would run 'go build'. \n")
		success = false
	}
	return pkgs, success, nil
}

// RemoveBadPackages takes the full list of packages and a map containing the packages that produced errors while being loaded.
func RemoveBadPackages(allPackages []*packages.Package, badPackages map[*packages.Package]bool) []*packages.Package {
	buf := new(strings.Builder)
	goodPackages := make([]*packages.Package, 0, len(allPackages))
	for _, pkg := range allPackages {
		if badPackages[pkg] {
			fmt.Fprintf(buf, "\n%s:\n", pkg.PkgPath)
			for _, pkgError := range pkg.Errors {
				fmt.Fprintf(buf, "- %s\n", pkgError.Error())
			}
		} else {
			goodPackages = append(goodPackages, pkg)
		}
	}
	fmt.Fprint(os.Stderr, buf.String())
	return goodPackages
}

// Run analyzers on a package
func RunAnalyzers(analyzers []*analysis.Analyzer, pkg *packages.Package) ([]util.Finding, error) {
	//run ssa first since the other analyzers require it

	ssaPass := &analysis.Pass{
		Analyzer:          buildssa.Analyzer,
		Fset:              pkg.Fset,
		Files:             pkg.Syntax,
		OtherFiles:        pkg.OtherFiles,
		IgnoredFiles:      pkg.IgnoredFiles,
		Pkg:               pkg.Types,
		TypesInfo:         pkg.TypesInfo,
		TypesSizes:        pkg.TypesSizes,
		ResultOf:          nil,
		Report:            nil,
		ImportObjectFact:  nil,
		ExportObjectFact:  nil,
		ImportPackageFact: nil,
		ExportPackageFact: nil,
		AllObjectFacts:    nil,
		AllPackageFacts:   nil,
	}

	ssaResult, err := ssaPass.Analyzer.Run(ssaPass)
	if err != nil {
		return nil, err
	}

	//feed the results of ssa into the other analyzers
	resultMap := make(map[*analysis.Analyzer]interface{})
	resultMap[buildssa.Analyzer] = ssaResult

	results := []util.Finding{}

	// Calculate number of Go files parsed
	full_size := 0
	pkg.Fset.Iterate(
		func(f *token.File) bool {
			full_size += 1
			return true
		})
	util.FilesFound = full_size

	for _, analyzer := range analyzers {
		//run the analyzer
		pass := &analysis.Pass{
			Analyzer:          analyzer,
			Fset:              pkg.Fset,
			Files:             pkg.Syntax,
			OtherFiles:        pkg.OtherFiles,
			IgnoredFiles:      pkg.IgnoredFiles,
			Pkg:               pkg.Types,
			TypesInfo:         pkg.TypesInfo,
			TypesSizes:        pkg.TypesSizes,
			ResultOf:          resultMap,
			Report:            func(d analysis.Diagnostic) {},
			ImportObjectFact:  nil,
			ExportObjectFact:  nil,
			ImportPackageFact: nil,
			ExportPackageFact: nil,
			AllObjectFacts:    nil,
			AllPackageFacts:   nil,
		}
		result, err := pass.Analyzer.Run(pass)
		if err != nil {
			return nil, err
		}
		results = append(results, (result.([]util.Finding))...)
	}
	return results, nil
}
