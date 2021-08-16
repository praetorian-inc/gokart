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
* There should be 2 vulnerability
 */

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
)

var (
	ctx context.Context

	db1 *sql.DB
)

func temp() string {
	return "a"
}
func query(x string) {
	a := "asdf"
	db1.Query("SELECT name FROM users WHERE username=" + a)
	db1.Query("SELECT name FROM users WHERE username=" + temp())
	db1.Query("SELECT name FROM users WHERE username=" + x)
	db1.Query(fmt.Sprintf("SELECT name FROM users WHERE username= %s", a))
	db1.Query(fmt.Sprintf("SELECT name FROM users WHERE username= %s", x))
}

func Sqlmain() {
	reader := bufio.NewReader(os.Stdin)
	hiddenMessage, _ := reader.ReadString('\n')
	query(hiddenMessage + "abc")
}
