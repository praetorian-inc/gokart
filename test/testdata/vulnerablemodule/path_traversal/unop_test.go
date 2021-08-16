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

package path_traversal

// Should print 1 vulnerability

import (
	"bufio"
	"os"
)

func unop_novuln() {
	hiddenMessage := "constt"
	tester := hiddenMessage
	a := &tester
	os.Open(*a)
}

func unop_vuln() {
	reader := bufio.NewReader(os.Stdin)
	hiddenMessage, _ := reader.ReadString('\n')
	tester := hiddenMessage
	a := &tester
	os.Open(*a)
}
