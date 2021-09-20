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
	"log"
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

// CloneModule clones a remote git repository
// An optional keyfile may be specified for use in ssh authentication
// If quiet is true, don't print clone progress to stdout
func CloneModule(dir string, url string, branch string, keyFile string, quiet bool) error {
	var cloneOptions git.CloneOptions

	cloneOptions = git.CloneOptions{
		URL: url,
	}

	if !quiet {
		log.Printf("Cloning new remote module: %s\n", url)
		cloneOptions.Progress = os.Stdout
	}

	if len(branch) != 0 {
		log.Printf("Cloning with remote branch reference: %s\n", branch)
		cloneOptions.ReferenceName = plumbing.NewBranchReferenceName(branch)
	}

	if len(keyFile) != 0 {
		_, err := os.Stat(keyFile)
		if err != nil {
			log.Printf("Read file %s failed %s\n", keyFile, err.Error())
			return err
		}

		// Clone the given repository to the given directory (password set to "")
		publicKeys, err := ssh.NewPublicKeysFromFile("git", keyFile, "")
		if err != nil {
			log.Printf("Generate publickeys from file %s failed: %s\n", keyFile, err.Error())
			return err
		}
		log.Printf("Authenticating with ssh keyfile: %s\n", keyFile)
		cloneOptions.Auth = publicKeys
	}

	_, err := git.PlainClone(dir, false, &cloneOptions)
	return err
}

//CleanupModule attempts to delete a directory.
func CleanupModule(dir string) error {
	err := os.RemoveAll(dir)
	return err
}
