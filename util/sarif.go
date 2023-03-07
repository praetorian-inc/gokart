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

	"github.com/owenrumney/go-sarif/sarif"
)

var SarifReport *sarif.Report
var SarifRun *sarif.Run

func InitSarifReporting() {
	report, err := sarif.New(sarif.Version210)
	SarifReport = report
	if err != nil {
		log.Fatal(err)
	}
	SarifRun = sarif.NewRun("GoKart", "https://github.com/garcia-jc/gokart")
}

func SarifRecordFinding(type_ string, message string, filename string, lineNumber int) {
	vulnLoc := sarif.NewLocationWithPhysicalLocation(sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewSimpleArtifactLocation(filename)).WithRegion(sarif.NewSimpleRegion(lineNumber, lineNumber)))
	SarifRun.AddResult(type_).WithMessage(sarif.NewTextMessage(message)).WithLocation(vulnLoc)
}

func SarifPrintReport() {
	SarifReport.AddRun(SarifRun)
	SarifReport.PrettyWrite(os.Stdout)
}
