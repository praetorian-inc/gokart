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

package cmd

import (
	"github.com/lithammer/dedent"
	"github.com/spf13/cobra"
)

var (
	goKartCmd = &cobra.Command{
		Use:   "gokart scan",
		Short: "A static analysis security scanner for Go",
		Long: dedent.Dedent(`
		╭────────────────────────── GoKart ──────────────────────────╮
		│                                                            │
		│   An open-source static analysis security scanner for Go   │
		│                                                            │
		│           https://github.com/garcia-jc/gokart         │
		│                                                            │
		╰────────────────────────────────────────────────────────────╯
		
		
		╭────────────────────── Example usage ───────────────────────╮
		│                                                            │
		│           	Recursively scan current directory           │
		│  ──────────────────────────────────────────────────────    │
		│  $ gokart scan <flags>                                     │
		│                                                            │
		│                   Scan specific directory                  │
		│  ──────────────────────────────────────────────────────    │
		│  $ gokart scan <directory> <flags>                         │
		│                                                            │
		│                     Get info about flags                   │
		│  ──────────────────────────────────────────────────────    │
		│  $ gokart scan -h                                          │
		│                                                            │
		╰────────────────────────────────────────────────────────────╯
	
		Please report any bugs or feature requests by opening a new
		issue at https://github.com/garcia-jc/gokart`),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
)

// Execute is a wrapper to call the GoKart root command
func Execute() error {
	return goKartCmd.Execute()
}

func init() {
	goKartCmd.CompletionOptions.DisableDefaultCmd = true
}
