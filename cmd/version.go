// Copyright 2021 Steven Roberts <sroberts@fenderq.com>
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

// Implementation of Semantic Versioning.
// https://semver.org/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

type Version struct {
	Major      int
	Minor      int
	Patch      int
	PreRelease string
}

func (v *Version) String() string {
	return fmt.Sprintf("%d.%d.%d%s",
		v.Major, v.Minor, v.Patch, v.PreRelease)
}

var (
	// Update the version information here.
	versionInfo = &Version{
		Major:      0,
		Minor:      4,
		Patch:      0,
		PreRelease: "",
	}
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("v%s\n", versionInfo)
		},
	}
)

func init() {
	goKartCmd.AddCommand(versionCmd)
}
