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
Package cmd implements a simple command line interface using cobra
*/
package cmd

import (
	"github.com/praetorian-inc/gokart/analyzers"
	"github.com/praetorian-inc/gokart/util"
	"github.com/spf13/cobra"
)

var yml string
var outputPath string

func init() {
	goKartCmd.AddCommand(scanCmd)
	scanCmd.Flags().BoolP("sarif", "s", false, "outputs findings in SARIF form")
	scanCmd.Flags().BoolP("globalsTainted", "g", false, "marks global variables as dangerous")
	scanCmd.Flags().BoolP("verbose", "v", false, "outputs full trace of taint analysis")
	scanCmd.Flags().BoolP("debug", "d", false, "outputs debug logs")
	scanCmd.Flags().StringVarP(&yml, "input", "i", "", "input path to custom yml file")
	scanCmd.Flags().StringVarP(&outputPath, "output", "o", "", "file path to write findings output instead of stdout")
	goKartCmd.MarkFlagRequired("scan")
}

var scanCmd = &cobra.Command{
	Use:   "scan [flags] [directory]",
	Short: "Scans a Go module directory",
	Long: `
Scans a Go module directory. To scan the current directory recursively, use gokart scan. To scan a specific directory, use gokart scan <directory>.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			// recursively scan the current directory if no arguments are passed in
			args = append(args, "./...")
		}
		sarif, _ := cmd.Flags().GetBool("sarif")
		globals, _ := cmd.Flags().GetBool("globalsTainted")
		verbose, _ := cmd.Flags().GetBool("verbose")
		debug, _ := cmd.Flags().GetBool("debug")
		util.InitConfig(globals, sarif, verbose, debug, outputPath, yml)
		analyzers.Scan(args)
	},
}
