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

// zero vulns should be reported

import (
	"os"
)

func getFile4(temp string) string {
	tmp := "./list1/images/"
	x := 5
	if x != 5 {
		tmp = "./etc/passwd"
	}
	DirTraversal6(tmp)
	return "str"
}

func DirTraversal6(folderPath string) {
	f, _ := os.Create(folderPath)
	f.Close()
}
