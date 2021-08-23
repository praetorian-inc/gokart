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
Package analyzers implements individual security scanners for Go
and a generic analyzer based on recursive taint propagation
*/
package analyzers

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/praetorian-inc/gokart/run"
	"github.com/praetorian-inc/gokart/util"
	"golang.org/x/tools/go/analysis"
)

var Analyzers = []*analysis.Analyzer{
	RsaKeylenAnalyzer,
	PathTraversalAnalyzer,
	SQLInjectionAnalyzer,
	CommandInjectionAnalyzer,
	SSRFAnalyzer,
}

func Scan(args []string) {
	if util.Config.OutputSarif {
		util.InitSarifReporting()
	} else {
		fmt.Printf("\nRevving engines VRMMM VRMMM\n3...2...1...Go!\n")
	}

	// If we're given a target path, we do some slight changes to make sure that
	// gokart will behave as expected. Specifically we turn the path into an absolute
	// path, and then we append /... to the end to make sure the package loading is recursive.
	// Finally we update the current working directory to the target
	if len(args) > 0 {
		target_path := args[0]
		if !filepath.IsAbs(target_path) {
			target_path, _ = filepath.Abs(args[0])
			args[0] = target_path
		}

		// Fix up the path to make sure it is pointed at a directory (even if given a file)
		fileInfo, err := os.Stat(strings.TrimRight(target_path, "."))
		if err != nil {
			log.Fatal(err)
		}
		target_dir := filepath.Dir(target_path)
		if fileInfo.IsDir() {
			// Adding an extra / to the end of the path to make sure we still target the directory
			target_dir = filepath.Dir(target_path + "/")
		}

		if !strings.HasSuffix(target_path, "...") {
			target_path = filepath.Join(target_dir, "...")
			args[0] = target_path
			if util.Config.Debug {
				fmt.Printf("Setting target_path to %s\n", args[0])
			}
		}

		err = os.Chdir(strings.TrimRight(target_path, "."))
		if err != nil {
			log.Fatal(err)
		}
		cwd, _ := os.Getwd()
		if util.Config.Debug {
			fmt.Printf("Current working directory is %s\n", cwd)
		}
	}

	generic_analyzers := LoadGenericAnalyzers()
	Analyzers = append(Analyzers, generic_analyzers[:]...)

	// Begin timer
	run_begin_time := time.Now()
	// Run analyzers
	results, success, err := run.Run(Analyzers, args...)
	if err != nil {
		log.Fatal(err)
	}
	// Calculate time taken
	scan_time := time.Since(run_begin_time)

	/* Unless the argument given is an absolute path, the path to the source file for findings are trimmed
	 * to be relative to the most specific path shared by the argument and the current working directory.
	 */
	parent_dir := ""
	if len(args) > 0 && !filepath.IsAbs(args[0]) {
		full_path, _ := filepath.Abs(args[0])
		full_path = strings.TrimSuffix(full_path, "...")
		cwd, _ := os.Getwd()
		full_path_split := strings.Split(full_path, "/")[1:]
		cwd_split := strings.Split(cwd, "/")[1:]
		i := 0
		for i < len(full_path_split) && i < len(cwd_split) && full_path_split[i] == cwd_split[i] {
			parent_dir += "/" + full_path_split[i]
			i++
		}
		parent_dir += "/"
	}

	count := 0
	for _, finding := range results {
		finding.Vulnerable_Function.SourceFilename = strings.TrimPrefix(finding.Vulnerable_Function.SourceFilename, parent_dir)
		if finding.Untrusted_Source != nil {
			for i, source := range finding.Untrusted_Source {
				finding.Untrusted_Source[i].SourceFilename = strings.TrimPrefix(source.SourceFilename, parent_dir)
			}
		}
		if util.OutputFinding(finding) {
			count++
		}
	}
	// if packages were able to be scanned, print the correct output message
	if util.Config.OutputSarif && success {
		util.SarifPrintReport()
		fmt.Println()
	} else if success {
		fmt.Println("\nRace Complete! Analysis took", scan_time, "and", util.FilesFound, "Go files were scanned (including imported packages)")
		fmt.Printf("GoKart found %d potentially vulnerable functions\n", count)
	}
}
