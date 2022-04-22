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

package types

import (
	"sort"
	"time"
)

type VersionSource string

const (
	SourceJAR      VersionSource = "jar"
	SourceClass    VersionSource = "class"
	SourceMetadata VersionSource = "metadata"
)

type Report struct {
	Version         string          `json:"version"`
	Hostname        string          `json:"hostname"`
	OS              string          `json:"os"`
	IPAddresses     []string        `json:"ip_addresses"`
	MACAddresses    []string        `json:"mac_addresses"`
	Timestamp       time.Time       `json:"timestamp"`
	Results         []ReportEntry   `json:"results"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type ReportEntry struct {
	PID         int32  `json:"pid"`
	ProcessName string `json:"process_name"`
	BinaryPath  string `json:"binary_path"`
	Command     string `json:"command"`

	// Environment variables
	Environ map[string]string `json:"env"`

	// List of system properties set for the process
	SystemProperties map[string]string `json:"system_properties"`

	// JAR files
	JARs []JAREntry `json:"jars"`

	// Log4J-related files in a JAR file
	Classes []FileEntry `json:"classes"`
}

type JAREntry struct {
	Path          string        `json:"path"`
	Version       string        `json:"version"`
	VersionSource VersionSource `json:"version_source,omitempty"`
	SHA256        string        `json:"sha256"`
}

type FileEntry struct {
	Path        string `json:"path"`
	ContainedIn string `json:"in,omitempty"`
	SHA256      string `json:"sha256"`
}

// Returns the property values in a consistently-sorted format
func (r ReportEntry) PropertyValues() []string {
	vs := make([]string, 0, len(r.SystemProperties))
	for _, key := range r.PropertyNames() {
		vs = append(vs, r.SystemProperties[key])
	}
	return vs
}

// Returns the property names in a consistently-sorted format.
func (r ReportEntry) PropertyNames() []string {
	ks := make([]string, 0, len(r.SystemProperties))
	for k := range r.SystemProperties {
		ks = append(ks, k)
	}

	sort.Strings(ks)
	return ks
}

func (r ReportEntry) UsingLog4j() bool {
	return len(r.JARs) > 0 || len(r.Classes) > 0
}

type Vulnerability struct {
	Hostname    string `json:"hostname"`
	Version     string `json:"version"`
	ProcessID   int32  `json:"process_id"`
	ProcessName string `json:"process_name"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
}
