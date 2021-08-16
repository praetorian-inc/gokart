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

/*
* There should be no vulnerabilities
 */

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
)

var (
	ctx2 context.Context
	db2  *sql.DB
)

func getSalt() string {
	return "5678"
}

func makequery(input string) {
	db2.Query("SELECT name FROM users WHERE username=" + input)
}

func makequery2(input string) {
	db2.Query("SELECT name FROM users WHERE username=" + input)
}

func makequery3(s string, i int) {
	db2.Query(fmt.Sprintf("SELECT name FROM users WHERE username= %s", s))
	db2.Query(fmt.Sprintf("SELECT name FROM users WHERE username=admin OR 1=%d", i))
	converted := strconv.Itoa(i)
	db2.Query("SELECT name FROM users WHERE username=admin OR 1=" + converted)
}

func middleman(hiddenMessage string) {
	salt := "1234"
	makequery(hiddenMessage + salt)
}

func middleman2(hiddenMessage string) {
	makequery2(hiddenMessage + getSalt())
}

func middleman3(hiddenMessage string, secretMessage int) {
	makequery3(hiddenMessage, secretMessage+5)
}

func toplevel() {
	hiddenMessage := "This is safe"
	middleman(hiddenMessage)
	middleman2(hiddenMessage)
	middleman3(hiddenMessage, 5)
}
