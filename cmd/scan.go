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
	"io/ioutil"
	"log"
	"os"

	"github.com/praetorian-inc/gokart/analyzers"
	"github.com/praetorian-inc/gokart/util"
	"github.com/spf13/cobra"
)

var yml string
var exitCode bool
var remoteModule string
var outputPath string
var remoteBranch string
var keyFile string

func init() {
	goKartCmd.AddCommand(scanCmd)
	scanCmd.Flags().BoolP("sarif", "s", false, "outputs findings in SARIF form")
	scanCmd.Flags().BoolP("json", "j", false, "outputs findings in JSON")
	scanCmd.Flags().BoolP("globalsTainted", "g", false, "marks global variables as dangerous")
	scanCmd.Flags().BoolP("verbose", "v", false, "outputs full trace of taint analysis")
	scanCmd.Flags().BoolP("debug", "d", false, "outputs debug logs")
	scanCmd.Flags().BoolP("exitCode", "x", false, "return non-nil exit code on potential vulnerabilities or scanner failure")
	scanCmd.Flags().StringVarP(&remoteModule, "remoteModule", "r", "", "Remote gomodule to scan")
	scanCmd.Flags().StringVarP(&remoteBranch, "remoteBranch", "b", "", "Branch of remote module to scan")
	scanCmd.Flags().StringVarP(&keyFile, "keyFile", "k", "", "SSH Keyfile to use for ssh authentication for remote git repository scanning")
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
		sarif, _ := cmd.Flags().GetBool("sarif")
		json, _ := cmd.Flags().GetBool("json")
		globals, _ := cmd.Flags().GetBool("globalsTainted")
		verbose, _ := cmd.Flags().GetBool("verbose")
		debug, _ := cmd.Flags().GetBool("debug")
		exitCode, _ := cmd.Flags().GetBool("exitCode")
		util.InitConfig(globals, sarif, json, verbose, debug, outputPath, yml, exitCode)

		// If remoteModule was set, clone the remote repository and scan it
		if len(remoteModule) != 0 {
			moduleTempDir, err := ioutil.TempDir(".", "gokart")
			if err != nil {
				log.Fatal("Error creating temporary directory: ", err.Error())
			}
			defer util.CleanupModule(moduleTempDir)

			// Clone the module, if the output format is JSON or SARIF don't print any progress to stdout
			err = util.CloneModule(moduleTempDir, remoteModule, remoteBranch, keyFile, json || sarif)

			if err != nil {
				util.CleanupModule(moduleTempDir)
				log.Fatal("Error cloning remote repository: ", err.Error())
			}
			// If passing in a module - the other arguments are wiped out!
			args = append([]string{}, moduleTempDir+"/...")
		}

		// recursively scan the current directory if no arguments are passed in
		if len(args) == 0 {
			args = append(args, "./...")
		}

		results, err := analyzers.Scan(args)
		// If we have set the flag to return non-zero exit code for when results are found or the scanner fails, return 1
		if exitCode && (err != nil || len(results) > 0) {
			os.Exit(1)
		}
	},
}
