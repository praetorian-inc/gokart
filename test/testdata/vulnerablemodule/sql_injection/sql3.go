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
* There should be 5 vulnerabilities
 */

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"strconv"
)

var (
	db4 *sql.DB
)

func three_getSalt() string {
	return "5678"
}

func three_makequery(input string) {
	db4.Query("SELECT name FROM users WHERE username=" + input)
}

func three_makequery2(input string) {
	db4.Query("SELECT name FROM users WHERE username=" + input)
}

func three_makequery3(s string, i int) {
	db4.Query(fmt.Sprintf("SELECT name FROM users WHERE username= %s", s))
	db4.Query(fmt.Sprintf("SELECT name FROM users WHERE username=admin OR 1=%d", i))
	converted := strconv.Itoa(i)
	db4.Query("SELECT name FROM users WHERE username=admin OR 1=" + converted)
}

func three_middleman(hiddenMessage string) {
	salt := "1234"
	three_makequery(hiddenMessage + salt)
}

func three_middleman2(hiddenMessage string) {
	three_makequery2(hiddenMessage + three_getSalt())
}

func three_middleman3(hiddenMessage string, secretMessage int) {
	three_makequery3(hiddenMessage, secretMessage+5)
}

func three_toplevel(unsafe int) {
	reader := bufio.NewReader(os.Stdin)
	hiddenMessage, _ := reader.ReadString('\n')
	three_middleman(hiddenMessage)
	three_middleman2(hiddenMessage)
	three_middleman3(hiddenMessage, unsafe)
}

func three_sqlmain() {
	reader := bufio.NewReader(os.Stdin)
	str, _ := reader.ReadString('\n')
	hiddenInt, _ := strconv.Atoi(str)
	three_toplevel(hiddenInt)
}
