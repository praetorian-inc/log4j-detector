// Copyright 2022 Praetorian Security, Inc.
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
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/praetorian-inc/log4j-remediation/pkg/build"
	"github.com/praetorian-inc/log4j-remediation/pkg/log4j"
	"github.com/praetorian-inc/log4j-remediation/pkg/types"
)

var (
	printversion bool
	outputjson   bool
	logFile      string
)

func main() {
	flag.StringVar(&logFile, "log", "log4j-remediation.log", "log file to parse")
	flag.BoolVar(&outputjson, "json", false, "output in json format")
	flag.BoolVar(&printversion, "v", false, "prints current version")
	flag.Parse()

	if printversion {
		fmt.Printf("log-reader version %s", build.Version)
		return
	}

	js := json.NewEncoder(os.Stdout)

	b, err := os.ReadFile(logFile)
	if err != nil {
		log.Fatalf("failed to read file: %s", err)
	}
	lines := bytes.Split(b, []byte("\n"))

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		var report types.Report
		err = json.Unmarshal(line, &report)
		if err != nil {
			log.Fatalf("failed to unmarshal json: %s", err)
		}

		for _, vuln := range log4j.DetectVulnerabilities(report) {
			if outputjson {
				js.Encode(vuln) // nolint:errcheck
			} else {
				fmt.Printf("%s: log4j version %s loaded by process [%d] %s in %s\n",
					vuln.Hostname, vuln.Version, vuln.ProcessID, vuln.ProcessName, vuln.Path)
			}
		}
	}
}
