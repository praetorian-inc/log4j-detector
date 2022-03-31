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

// Searches the system for artifacts related to vulerable lib and prints them to stdout

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/shirou/gopsutil/process"

	"github.com/praetorian-inc/log4j-remediation/pkg/build"
	"github.com/praetorian-inc/log4j-remediation/pkg/types"
)

var (
	printversion      bool
	verbose           bool
	reportAddr        string
	defaultReportAddr string
)

func main() {
	flag.BoolVar(&verbose, "verbose", false, "be more verbose")
	flag.StringVar(&reportAddr, "server", defaultReportAddr, "url of reporting server")
	flag.BoolVar(&printversion, "v", false, "prints current version")
	flag.Parse()

	if printversion {
		fmt.Printf("detector version %s", build.Version)
		return
	}

	defer log.Printf("done")

	rc := NewReportClient(reportAddr)
	err := rc.HealthCheck()
	if err != nil {
		log.Printf("failed to connect to report server: %s", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = Unknown
	}

	var ips []string
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, err := iface.Addrs() // nolint:govet
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ips = append(ips, a.String())
		}
	}

	if verbose {
		log.Printf("fetching processes")
	}

	procs, err := process.Processes()
	if err != nil {
		log.Fatalf("error getting processes: %+v", err) //nolint:gocritic
	}

	if verbose {
		log.Printf("running scan of %d processes", len(procs))
	}

	report := makeReport(procs)

	if verbose {
		log.Printf("finished scan with %d results", len(report))
	}

	// Sort by the PID
	sort.SliceStable(report, func(i, j int) bool {
		return report[i].PID < report[j].PID
	})

	r := types.Report{
		Version:     build.Version,
		Hostname:    hostname,
		OS:          runtime.GOOS,
		IPAddresses: ips,
		Timestamp:   time.Now(),
		Results:     report,
	}

	r.Vulnerabilities = DetectVulnerabilities(r)

	if verbose {
		log.Printf("sending report to %s", reportAddr)
	}

	err = rc.SendReport(r)
	if err != nil {
		log.Println(err)
	}

	err = json.NewEncoder(os.Stdout).Encode(r)
	if err != nil {
		log.Println(err)
	}
    

	log.Println("--")
	for _, vuln := range r.Vulnerabilities {
		log.Printf("RISK: %s using vulnerable lib %s in process [%d] %s at %s",
			vuln.Hostname, vuln.Version, vuln.ProcessID, vuln.ProcessName, vuln.Path)

	}

}

func makeReport(procs []*process.Process) (ret []types.ReportEntry) {
	ownpid := os.Getpid()
	for _, proc := range procs {
		// skip self
		if int(proc.Pid) == ownpid {
			continue
		}

		if verbose {
			log.Printf("[%d] started scanning", proc.Pid)
		}

		name, err := proc.Name()
		if err != nil {
			log.Printf("error getting name for process pid=%d", proc.Pid)
			name = Unknown
		}

		if verbose {
			log.Printf("[%d] name %s", proc.Pid, name)
		}

		processPath := Unknown
		if s, err := proc.Exe(); err == nil {
			processPath = s
		}

		if verbose {
			log.Printf("[%d] exe %s", proc.Pid, processPath)
		}

		// skip system32
		if strings.HasPrefix(processPath, `C:\Windows\System32`) {
			continue
		}

		cmdline, _ := proc.Cmdline()

		if verbose {
			log.Printf("[%d] cmdline %s", proc.Pid, cmdline)
		}

		entry := types.ReportEntry{
			PID:              proc.Pid,
			ProcessName:      name,
			BinaryPath:       processPath,
			Command:          cmdline,
			Environ:          make(map[string]string),
			SystemProperties: make(map[string]string),
		}
		if props, err := getSysprops(proc); err == nil {
			// log.Printf("sysprops[%d] = %+v", proc.Pid, props)
			entry.SystemProperties = props
		} else {
			if err := checkCommandline(proc, &entry); err != nil {
				log.Printf("%v", err)
			}
		}
		if err := checkOpenFiles(proc, &entry); err != nil {
			log.Printf("%v", err)
			continue
		}
		if env, err := proc.Environ(); err == nil {
			for _, s := range env {
				parts := strings.SplitN(s, "=", 2)
				if len(parts) == 2 {
					entry.Environ[parts[0]] = parts[1]
				}
			}
		}

		if len(entry.JARs) == 0 && len(entry.Classes) == 0 {
			continue
		}

		ret = append(ret, entry)
	}

	return
}

func checkOpenFiles(proc *process.Process, entry *types.ReportEntry) error {
	if verbose {
		log.Printf("[%d] checking open files", proc.Pid)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	files, err := proc.OpenFilesWithContext(ctx)
	if err != nil {
		return fmt.Errorf("error getting open files for process %q (pid: %d): %w", entry.ProcessName, proc.Pid, err)
	}

	if verbose {
		log.Printf("[%d] processing %d open files", proc.Pid, len(files))
	}

	for _, file := range files {
		if verbose {
			log.Printf("[%d] scanning file %s", proc.Pid, file.Path)
		}

		if strings.Contains(file.Path, "spring") {
			zr, err := zip.OpenReader(file.Path)
			if err != nil {
				continue
			}

			entry.JARs = append(entry.JARs, jarEntryFromZip(file.Path, &zr.Reader))
			zr.Close()
		}

		if strings.HasSuffix(strings.ToLower(file.Path), ".jar") {
			if err := checkJarFile(entry, file); err != nil {
				return fmt.Errorf("error checking JAR file %q for process %q (pid: %d): %w",
					file.Path, entry.ProcessName, proc.Pid, err)
			}
		}
	}

	return nil
}

func checkCommandline(proc *process.Process, entry *types.ReportEntry) error {
	cmdline, err := proc.CmdlineSlice()
	if err != nil {
		return fmt.Errorf("error getting command line for process %q (pid: %d): %w", entry.ProcessName, proc.Pid, err)
	}

	for _, part := range cmdline {
		if strings.HasPrefix(part, "-D") {
			parts := strings.SplitN(part[2:], "=", 2)
			if len(parts) == 2 {
				entry.SystemProperties[parts[0]] = parts[1]
			}
		}
	}

	return nil
}

func checkJarFile(entry *types.ReportEntry, openFile process.OpenFilesStat) error {
	f, err := os.Open(openFile.Path)
	if err != nil {
		return fmt.Errorf("error opening file %q: %w", openFile.Path, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("error calling Stat() on file %q: %w", openFile.Path, err)
	}

	// Ignore things that aren't files
	if !fi.Mode().IsRegular() {
		return nil
	}

	r, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return fmt.Errorf("error opening file %q: %w", openFile.Path, err)
	}

	// Check for the JndiLookup and JndiManager classes
	for _, f := range r.File {
		if strings.Contains(f.Name, "JndiLookup.class") ||
			strings.Contains(f.Name, "JndiManager.class") {
			fr, err := r.Open(f.Name)
			if err != nil {
				continue
			}

			hash := hashFsFile(fr)
			fr.Close()

			entry.Classes = append(entry.Classes, types.FileEntry{
				ContainedIn: openFile.Path,
				Path:        f.Name,
				SHA256:      hash,
			})
		}
	}

	jar := jarEntryFromZip(openFile.Path, r)
	if jar.Version != Unknown && jar.VersionSource != types.SourceMetadata {
		entry.JARs = append(entry.JARs, jar)
	}

	return nil
}

func getSysprops(proc *process.Process) (map[string]string, error) {
	// Use the jinfo from "next" to the java process, if it exists
	jinfoPath := "/usr/bin/jinfo"
	if s, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", proc.Pid)); err == nil {
		tpath := filepath.Join(filepath.Dir(s), "jinfo")
		if fileExists(tpath) {
			jinfoPath = tpath
		}
	}
	if !fileExists(jinfoPath) {
		return nil, fmt.Errorf("no jinfo found")
	}

	var stdout bytes.Buffer
	cmd := exec.Command(jinfoPath, fmt.Sprint(proc.Pid)) // nolint:gosec
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	ret := make(map[string]string)
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "=", 2)
		if len(parts) == 2 {
			ret[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ret, nil
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