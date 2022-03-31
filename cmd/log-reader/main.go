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

	"github.com/hashicorp/go-version"
	"github.com/praetorian-inc/log4j-remediation/pkg/build"
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

		for _, vuln := range DetectVulnerabilities(report) {
			if outputjson {
				js.Encode(vuln) // nolint:errcheck
			} else {
				fmt.Printf("%s: vulnerable version %s loaded by process [%d] %s in %s\n",
					vuln.Hostname, vuln.Version, vuln.ProcessID, vuln.ProcessName, vuln.Path)
			}
		}
	}
}

// Per https://tanzu.vmware.com/security/cve-2022-22965
var (
	// Version fixes vulnerability.
	fixedVersion_5_3 = version.Must(version.NewVersion("5.3.18"))
	fixedVersion_5_2 = version.Must(version.NewVersion("5.2.20"))
)

func DetectVulnerabilities(report types.Report) []types.Vulnerability {
	var vulns []types.Vulnerability

	for _, r := range report.Results {
		var vulnerableJAR *types.JAREntry

		for i, jar := range r.JARs {

			v, err := version.NewVersion(jar.Version)
			if err != nil {
				continue
			}
			fmt.Printf("Processing jar %s: version %s\n", jar.Path, jar.Version)

			if v.Equal(fixedVersion_5_2) {
			     fmt.Printf("Ignored (fixed) 5.2.x jar %s: version %s\n", jar.Path, jar.Version)
				continue
			}
            
			if v.Equal(fixedVersion_5_3) {
			     fmt.Printf("Ignored (fixed) 5.3.x jar %s: version %s\n", jar.Path, jar.Version)
				continue
			}

			if v.LessThan(fixedVersion_5_2) || v.LessThan(fixedVersion_5_3) {
			    fmt.Printf("Match for  jar %s: version %s\n", jar.Path, jar.Version)
				vulnerableJAR = &r.JARs[i]
			}
		}

		if vulnerableJAR == nil {
			continue
		}

		// If we get here, we're vulnerable
		vulns = append(vulns, types.Vulnerability{
			Hostname:    report.Hostname,
			ProcessID:   r.PID,
			ProcessName: r.ProcessName,
			Version:     vulnerableJAR.Version,
			Path:        vulnerableJAR.Path,
			SHA256:      vulnerableJAR.SHA256,
		})
	}

	return vulns
}