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

func TestSSRF(t *testing.T) {
	testFiles := []string{
		"ssrf.go",
		"ssrf_alloc_taint.go",
		"ssrf_client.go",
		"ssrf_client_good.go",
		"ssrf_good.go",
		"ssrf_client_control.go",
		"ssrf_struct.go",
	}

	// Append directory to each entry
	for i := 0; i < len(testFiles); i++ {
		testFiles[i] = "ssrf/" + testFiles[i]
	}

	testResults := []int{
		1,
		1,
		1,
		0,
		0,
		0,
		1,
	}
	for i := 0; i < len(testFiles); i++ {
		t.Run(testFiles[i], func(t *testing.T) {
			testutil.RunTest(testFiles[i], testResults[i], "CWE-918: Server-Side Request Forgery", SSRFAnalyzer, t)
		})
	}
}
