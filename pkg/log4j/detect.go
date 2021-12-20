// Copyright (c) 2021- Stripe, Inc. (https://stripe.com)
// This code is licensed under MIT license (see LICENSE-MIT for details)

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

package log4j

import (
	"github.com/hashicorp/go-version"

	"github.com/praetorian-inc/log4j-remediation/pkg/types"
)

// Per https://logging.apache.org/log4j/2.x/security.html
var (
	// Versions before 2.0-beta9 are not vulnerable.
	version2 = version.Must(version.NewVersion("2.0.0"))

	// Version 2.12.2 (for Java 7) removes Message Lookups and disables JNDI lookups by default.
	excludeVersion = version.Must(version.NewVersion("2.12.2"))

	// Version 2.16.0 (for Java 8+) removes Message Lookups and disables JNDI lookups by default.
	fixedVersion = version.Must(version.NewVersion("2.16.0"))
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

			if v.LessThan(version2) {
				continue
			}

			if v.Equal(excludeVersion) {
				continue
			}

			if v.LessThan(fixedVersion) {
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
