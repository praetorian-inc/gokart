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

	"github.com/garcia-jc/gokart/test/testutil"
)

func TestCommandInjection(t *testing.T) {
	testFiles := []string{
		"command_context_injection_safe.go",
		"command_injection.go",
		"commandContext.go",
	}

	// Append directory to each entry
	for i := 0; i < len(testFiles); i++ {
		testFiles[i] = "command_injection/" + testFiles[i]
	}

	testResults := []int{
		0,
		2,
		2,
	}
	for i := 0; i < len(testFiles); i++ {
		t.Run(testFiles[i], func(t *testing.T) {
			testutil.RunTest(testFiles[i], testResults[i], "CWE-78: OS Command Injection", CommandInjectionAnalyzer, t)
		})
	}
}
