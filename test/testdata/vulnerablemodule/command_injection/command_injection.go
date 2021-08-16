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

// 2 vulnerabilities should be reported, on lines 28, 34
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
)

func get_user_input() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter command: ")
	text, _ := reader.ReadString('\n')
	return text
}

func constant_func() string {
	return "test1" + "test2"
}

func no_command_injection() {
	msg := "This echo is safe."
	cmd := exec.Command("echo", msg, "Yes it is.")
	cmd.Run()
}

func command_injection_user_input() {
	text := get_user_input()
	cmd := exec.Command("sh", "echo", "hi", "&&", text)
	cmd.Run()
}

func command_injection_firstarg() {
	msg := get_user_input()
	cmd := exec.Command(msg, "echo", "hi")
	cmd.Run()
}

func no_command_injection_function() {
	msg := constant_func()
	cmd := exec.Command("sh", "echo", "hi", "&&", msg)
	cmd.Run()
}

func command_injection_main() {
	no_command_injection()
	command_injection_user_input()
	command_injection_firstarg()
	no_command_injection_function()
}
