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

package util

import (
	"github.com/go-git/go-git/v5"
	"fmt"
	"strings"
	"os"
	"errors"
)

// CloneModule clones a remote git repository over HTTP.
func CloneModule(dir string, url string) error {
	// fmt.Printf("git clone %s\n", url)
	fmt.Printf("Loading new racetrack: %s\n",url)
	_, err := git.PlainClone(dir, false, &git.CloneOptions{
		URL: url,
		Progress: os.Stdout,
	})
	if err != nil {
		return err
	}
	return nil
}

//CleanupModule attempts to delete a directory.
func CleanupModule(dir string) error {
	err := os.Remove(dir)
	if err != nil{
		return err
	}
	return nil
}

// ParseModuleName returns a directory from a module path 
func ParseModuleName(mn string) (string, error) {

	if len(mn) == 0 {
		return "", errors.New("No module name provided")
	}

	modSlice := strings.Split(mn, "/")
	if len(modSlice) <= 1 {
		return "", errors.New("Invalid remote module name!\nMust be in format of: github.com/praetorian/gokart")
	}

	dirName := modSlice[len(modSlice)-1:][0]
	return dirName, nil


}