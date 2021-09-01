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

package util

import (
	"fmt"
	"log"
	"strings"

	"github.com/fatih/color"
)

// Finding represents a single vulnerability
type Finding struct {
	message             string
	Vulnerable_Function TaintedCode
	Untrusted_Source    []TaintedCode
	Type                string
}

// Create a finding object
func MakeFinding(message string, vulnerable_function TaintedCode, untrusted_source []TaintedCode, finding_type string) Finding {
	return Finding{
		message:             message,
		Vulnerable_Function: vulnerable_function,
		Untrusted_Source:    untrusted_source,
		Type:                finding_type,
	}
}

func StripArguments(parentFunction string) string {
	functionName := strings.Split(parentFunction, "(")[0]
	functionReturn := ""
	if splitOnClose := strings.Split(parentFunction, ")"); len(splitOnClose) > 1 {
		functionReturn = splitOnClose[1]
	}
	return strings.TrimSpace(functionName) + "(...)" + functionReturn
}

// returns true if the finding was valid and false if the finding had the same source and sink
func IsValidFinding(finding Finding) bool {
	if len(finding.Untrusted_Source) == 0 {
		return false
	}
	if finding.Vulnerable_Function.SourceCode == finding.Untrusted_Source[0].SourceCode {
		// if the source and sink are the same, return false and do not print out the finding
		return false
	}
	// add filtering for findings with chan sources
	if strings.Contains(finding.Untrusted_Source[0].SourceCode, "make(chan") {
		if Config.Debug {
			log.Printf("Filtering Finding for Source: %s\n", finding.Untrusted_Source[0].SourceCode)
		}
		return false
	}
	return true
}

// prints out a finding
func OutputFinding(finding Finding) {
	if Config.OutputSarif {
		SarifRecordFinding(finding.Type, finding.message, finding.Vulnerable_Function.SourceFilename,
			finding.Vulnerable_Function.SourceLineNum)
	} else {
		yellow := color.New(color.FgYellow).SprintFunc()
		cyan := color.New(color.FgCyan).SprintFunc()
		green := color.New(color.FgGreen).SprintFunc()

		parentFunctionArgs := finding.Vulnerable_Function.ParentFunction
		parentFunctionNoArgs := StripArguments(finding.Vulnerable_Function.ParentFunction)

		fmt.Printf("\n(%s) %s\n\n", cyan(finding.Type), yellow(finding.message))
		fmt.Printf("%s:%d\nVulnerable Function: [ %s ]\n", finding.Vulnerable_Function.SourceFilename, finding.Vulnerable_Function.SourceLineNum, parentFunctionNoArgs)
		fmt.Printf("      %d:\t%s\n", finding.Vulnerable_Function.SourceLineNum-1, GrabSourceCode(finding.Vulnerable_Function.SourceFilename, finding.Vulnerable_Function.SourceLineNum-1))
		fmt.Printf("    > %d:\t%s\n", finding.Vulnerable_Function.SourceLineNum, finding.Vulnerable_Function.SourceCode)
		fmt.Printf("      %d:\t%s\n", finding.Vulnerable_Function.SourceLineNum+1, GrabSourceCode(finding.Vulnerable_Function.SourceFilename, finding.Vulnerable_Function.SourceLineNum+1))

		if finding.Untrusted_Source != nil {

			source := finding.Untrusted_Source[0]
			fmt.Printf("\n%s:%d\n", source.SourceFilename, source.SourceLineNum)
			fmt.Printf("Source of Untrusted Input: [ %s ]\n", parentFunctionNoArgs)
			fmt.Printf("      %d:\t%s\n", source.SourceLineNum-1, GrabSourceCode(source.SourceFilename, source.SourceLineNum-1))
			fmt.Printf("    > %d:\t%s\n", source.SourceLineNum, source.SourceCode)
			fmt.Printf("      %d:\t%s\n", source.SourceLineNum+1, GrabSourceCode(source.SourceFilename, source.SourceLineNum+1))

			if Config.Verbose {
				fmt.Print(green("\n############################### FULL TRACE ###############################\n"))
				fmt.Printf("\nUntrusted Input Source:")
				for _, source := range finding.Untrusted_Source {
					fmt.Printf("%s:%d:\n[ %s ]\n>>>\t%s\n", source.SourceFilename,
						source.SourceLineNum, parentFunctionArgs, strings.TrimLeft(source.SourceCode, " \t"))
				}
			}

		}
		fmt.Printf("------------------------------------------------------------------------------\n")
	}
}
