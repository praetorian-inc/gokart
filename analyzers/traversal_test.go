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
	"testing"

	"github.com/praetorian-inc/gokart/test/testutil"
)

func TestPathTraversal(t *testing.T) {
	testFiles := []string{
		"path1.go",
		"path2.go",
		"path3.go",
		"path4.go",
		"pathBin.go",
		"pathBinPhi.go",
		"pathMultiParams.go",
		"pathPhi.go",
		"pathReg.go",
	}

	// Append directory to each entry
	for i := 0; i < len(testFiles); i++ {
		testFiles[i] = "path_traversal/" + testFiles[i]
	}

	testResults := []int{
		5,
		1,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
	}
	for i := 0; i < len(testFiles); i++ {
		t.Run(testFiles[i], func(t *testing.T) {
			testutil.RunTest(testFiles[i], testResults[i], "Path Traversal", PathTraversalAnalyzer, t)
		})
	}
}
