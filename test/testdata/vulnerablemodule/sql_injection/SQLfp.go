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
	"database/sql"
	"net/http"
)

var (
	db *sql.DB
)

func executeQuery(query string) {
	db.Query(query)
}

func formatQuery(field string, table string, user string) string {
	return "SELECT " + field + " FROM " + table + " WHERE username=" + user
}

func HTTPHandler(w http.ResponseWriter, r *http.Request) {
	FIELD := "name"
	TABLE := "users"

	response := r.URL.Query()["users"]
	user := response[0]

	executeQuery(formatQuery(FIELD, TABLE, user))
}

func main2() {
	http.HandleFunc("/", HTTPHandler)
	http.ListenAndServe(":8080", nil)
}
