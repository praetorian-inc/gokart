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

import (
	"net/http"
	"path/filepath"
)

func twitterMain() {
	http.HandleFunc("/", DirPathTraversalHandler)
	http.ListenAndServe(":8080", nil)
}

func DirPathTraversalHandler(w http.ResponseWriter, r *http.Request) {
	var pwd string
	params := r.URL.Query()
	appName := params.Get(":app")
	dirFile(filepath.Join(pwd, "/admin/builds/"+appName+"-build/static/"), "/admin/"+appName+"/static/", r.URL.Path)
	//serveFile(w, r, dir, file)
}

func dirFile(test string, test2 string, test3 string) {
}
