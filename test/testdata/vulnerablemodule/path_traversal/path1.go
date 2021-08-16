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

// Expect 7 vulnerabilities found

import (
	"bufio"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
)

func DirTraversal1(filename string, folderPath string) {
	os.Create(folderPath + filename)
	os.Open(folderPath + filename)
	os.OpenFile(folderPath+filename, os.O_RDONLY, 0775)
	ioutil.ReadFile(folderPath + filename)
	ioutil.WriteFile(folderPath+filename, []byte("Hello, Gophers!"), 0775)
	path.Join(folderPath, filename)
	filepath.Join(folderPath, filename)
}

func tempTest() {
	reader := bufio.NewReader(os.Stdin)
	hiddenMessage, _ := reader.ReadString('\n')
	hiddenMessage2 := "hidden2"
	DirTraversal1(hiddenMessage, hiddenMessage2)
}
