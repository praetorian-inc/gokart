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

package main

import (
	"crypto/rand"
	"crypto/rsa"
)

//There should be one insufficient key length in this file

func multipleParams() int {
	tmp2 := 500
	tmp3 := 1000
	keylenMultParam(tmp2, tmp3)
	return tmp2
}

func keylenMultParam(tmp2 int, tmp3 int) {

	rsa.GenerateKey(rand.Reader, tmp2+tmp3)
}
