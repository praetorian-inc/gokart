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

GoKart is a scanner for go applications

Run it in the go module directory of the module you want to scan with gokart scan

GoKart is split up into a series of analyzers that each look for a specific vulnerability class. These are contained in
the `gokart/analyzers` package.

GoKart uses SSA to track the sources of data, to perform taint analysis. This means that GoKart can track how data flows
through an application, to remove false positives from data that comes from a trusted source
*/

package main

import (
	"fmt"
	"os"

	"github.com/praetorian-inc/gokart/cmd"
)

func main() {
	err := cmd.Execute()
	if err != nil {
		fmt.Printf("\nError: %s\n\nTry \"gokart help\" to steer GoKart in the right direction.\n\n", err)
		os.Exit(1)
	}
}
