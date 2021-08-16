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
* There should be 2 vulnerabilities
 */

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
)

var (
	ctx3 context.Context
	db3  *sql.DB
)

func four_makequery3(s string, i int) {
	//db3.Query(fmt.Sprintf("SELECT name FROM users WHERE username= %s", s))
	//db3.Query(fmt.Sprintf("SELECT name FROM users WHERE username=admin OR 1=%d", i))
	//converted := strconv.Itoa(i)
	//db3.Query("SELECT name FROM users WHERE username=admin OR 1=" + converted)
	db3.Query(fmt.Sprintf("SELECT 1 = %s", s))
	db3.Query(fmt.Sprintf("SELECT 2=%d", i))
	converted := strconv.Itoa(i)
	db3.Query("SELECT 3=" + converted)
}

func four_sqlmain() {
	reader := bufio.NewReader(os.Stdin)
	str, _ := reader.ReadString('\n')
	hiddenInt, _ := strconv.Atoi(str)
	four_makequery3("string", hiddenInt)
}
