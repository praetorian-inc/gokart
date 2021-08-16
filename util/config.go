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
	_ "embed"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ConfigType stores booleans for GoKart analysis configuration
type ConfigType struct {
	GlobalsSafe bool
	OutputSarif bool
	Debug       bool
	Verbose     bool
	YMLPath     string
}

var (
	FilesFound      = 0
	VulnGlobalVars  map[string][]string
	VulnGlobalFuncs map[string][]string
	VulnTypes       map[string][]string
	//go:embed analyzers.yml
	DefaultAnalyzersContent []byte
)

var Config ConfigType

func LoadVulnerableSources() {
	// Load YAML
	yamlPath := Config.YMLPath
	// If not found in the working directory, use the one in the executable's directory
	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		execPath, err := os.Executable()
		if err != nil {
			log.Fatal(err)
		}
		yamlPath = path.Join(path.Dir(execPath), yamlPath)
	}
	yfile, err := ioutil.ReadFile(yamlPath)
	if err != nil {
		log.Fatal(err)
	}

	data := make(map[interface{}]map[interface{}]map[interface{}]interface{})
	err = yaml.Unmarshal(yfile, &data)
	if err != nil {
		log.Fatal(err)
	}

	skeys := data["sources"]
	if Config.Debug {
		log.Println("Beginning list of sources defined in yml:")
	}
	for _, sdict := range skeys {
		for stype, sTypeDict := range sdict {
			callsmap := sTypeDict.(map[string]interface{})
			vulnmap := make(map[string][]string)

			for package_name, package_vuln_funcs := range callsmap {
				// Initialize an empty array if the map key does not exist
				if _, ok := vulnmap[package_name]; !ok {
					var empty_array []string
					vulnmap[package_name] = empty_array
				}
				package_vuln_funcs_arr := package_vuln_funcs.([]interface{})
				for i, val := range package_vuln_funcs_arr {
					if Config.Debug {
						log.Println("Function", package_vuln_funcs_arr[i], "in package", package_name)
					}
					vulnmap[package_name] = append(vulnmap[package_name], val.(string))
				}
			}

			// Set the map of vulnerable sources of this type
			if stype == "variables" {
				VulnGlobalVars = vulnmap
			} else if stype == "functions" {
				VulnGlobalFuncs = vulnmap
			} else if stype == "types" {
				VulnTypes = vulnmap

			}
		}
	}
	if Config.Debug {
		log.Println("List of sources complete")
	}
}

// InitConfig() parses the flags and sets the corresponding Config variables
func InitConfig(globals bool, sarif bool, verbose bool, debug bool, yml string) {

	flag.Parse()

	// If the YAML path provided is a relative path, convert it to absolute
	if yml != "" && !filepath.IsAbs(yml) {
		yml, _ = filepath.Abs(yml)
	}

	// If the YAML path provided is empty or doesn't exist, then load from the default of ~/.gokart/analyzers.yml
	if _, err := os.Stat(yml); os.IsNotExist(err) {
		if yml != "" {
			fmt.Printf("Custom analyzers config file not found at %q. ", yml)
		}
		fmt.Println("Using default analyzers config found at \"~/.gokart/analyzers.yml\".")

		// Load YAML
		config_path := os.ExpandEnv("$HOME/.gokart")
		yaml_path := path.Join(config_path, "analyzers.yml")
		yml = yaml_path

		// Create our config directory if it doesn't already exist
		if _, err := os.Stat(config_path); os.IsNotExist(err) {
			err = os.Mkdir(config_path, 0744)
			if err != nil {
				log.Fatal(err)
			}
		}

		// If not found in the working directory, use the one in the executable's directory
		if _, err := os.Stat(yaml_path); os.IsNotExist(err) {
			// default_analyzers_content is populated using the go:embed directive above
			err := ioutil.WriteFile(yaml_path, DefaultAnalyzersContent, 0744)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("No existing analyzers.yml file found - writing default to ~/.gokart/analyzers.yml")
		}
	}

	Config.GlobalsSafe = !globals
	Config.OutputSarif = sarif
	Config.Debug = debug
	Config.Verbose = verbose
	Config.YMLPath = yml
	LoadVulnerableSources()
}
