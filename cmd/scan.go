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
	"github.com/go-git/go-git/v5"
	"fmt"
	"strings"
	"os"
)

var yml string
var gomodname string

func init() {
	goKartCmd.AddCommand(scanCmd)
	scanCmd.Flags().BoolP("sarif", "s", false, "outputs findings in SARIF form")
	scanCmd.Flags().BoolP("globalsTainted", "g", false, "marks global variables as dangerous")
	scanCmd.Flags().BoolP("verbose", "v", false, "outputs full trace of taint analysis")
	scanCmd.Flags().BoolP("debug", "d", false, "outputs debug logs")
	scanCmd.Flags().StringVarP(&yml, "input", "i", "", "input path to custom yml file")
	scanCmd.Flags().StringVarP(&gomodname, "remoteModule", "r", "", "Remote gomodule to scan")
	goKartCmd.MarkFlagRequired("scan")
}

var scanCmd = &cobra.Command{
	Use:   "scan [flags] [directory]",
	Short: "Scans a Go module directory",
	Long: `
Scans a Go module directory. To scan the current directory recursively, use gokart scan. To scan a specific directory, use gokart scan <directory>.`,
	Run: func(cmd *cobra.Command, args []string) {
		sarif, _ := cmd.Flags().GetBool("sarif")
		globals, _ := cmd.Flags().GetBool("globalsTainted")
		verbose, _ := cmd.Flags().GetBool("verbose")
		debug, _ := cmd.Flags().GetBool("debug")
		util.InitConfig(globals, sarif, verbose, debug, yml)
		if len(gomodname) != 0 {
			fmt.Printf("Loading remote go module: %s\n", gomodname)
			modSlice := strings.Split(gomodname, "/")
			if len(modSlice) <= 1 {
				fmt.Printf("Invalid remote module name!\n")
				os.Exit(1)
			}
			dirName := modSlice[len(modSlice)-1:][0]
			fmt.Printf("git clone %s\n", gomodname)
			_,err := os.Stat("./"+dirName)
			if err == nil {
				//There is already a directory here
				fmt.Printf("Directory has already been cloned.\nPlease either delete it and try again or cd into it and run 'gokart scan'\n")
				os.Exit(1)
			}
			_, err = git.PlainClone("./"+dirName, false, &git.CloneOptions{
				URL: "https://"+ gomodname,
				Progress: os.Stdout,
			})
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			args = append(args,"./"+dirName+"/..." )
		}
		if len(args) == 0 {
			// recursively scan the current directory if no arguments are passed in
			args = append(args, "./...")
		}


		analyzers.Scan(args)
	},
}
