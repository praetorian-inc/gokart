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

package testutil

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/praetorian-inc/gokart/run"
	"golang.org/x/tools/go/analysis"
)

func RunTest(file string, numResults int, resultsType string, analyzer *analysis.Analyzer, t *testing.T) {
	_, b, _, _ := runtime.Caller(0)
	basepath := filepath.Dir(b)
	path := basepath + "/../testdata/vulnerablemodule/" + file
	results, _, err := run.Run([]*analysis.Analyzer{analyzer}, "file="+path)
	if err != nil {
		t.Error(err)
	}
	if len(results) != numResults {
		t.Errorf("Expected %d results, found %d", numResults, len(results))
	}
	for _, result := range results {
		if result.Type != resultsType {
			t.Errorf("Expected type %s, found %s", resultsType, results[0].Type)
		}
	}
}
