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

package main

import (
	"archive/zip"
	"bufio"
	"log"
	"os"
	"strings"

	"github.com/praetorian-inc/log4j-remediation/pkg/types"
)

const (
	Unknown         = "unknown"
	ApacheLog4jCore = "Apache Log4j Core"
)

func jarEntryFromZip(path string, r *zip.Reader) types.JAREntry {
	src, ver, hash := versionFromJARArchive(path, r)
	if hash == "" {
		hash = hashFile(path)
	}

	return types.JAREntry{
		Path:          path,
		Version:       ver,
		VersionSource: src,
		SHA256:        hash,
	}
}

func versionFromJARArchive(path string, r *zip.Reader) (src types.VersionSource, version, hash string) {
	if ver, hash := versionFromJARFingerprint(path); ver != Unknown {
		return types.SourceJAR, ver, hash
	}
	if ver, hash := versionFromJARArchiveFingerprint(r); ver != Unknown {
		return types.SourceClass, ver, hash
	}
	if ver := versionFromJARArchiveMeta(r); ver != Unknown {
		return types.SourceMetadata, ver, ""
	}

	return "", Unknown, ""
}

func versionFromJARFingerprint(path string) (version, hash string) {
	f, err := os.Open(path)
	if err != nil {
		return Unknown, ""
	}
	defer f.Close()

	hash = hashFsFile(f)

	for _, fp := range log4jArchiveFingerprints {
		if hash == fp.sha256 {
			if verbose {
				log.Printf("found log4j version %q by fingerprint", fp.version)
			}
			return fp.version, hash
		}
	}

	return Unknown, ""
}

func versionFromJARArchiveFingerprint(r *zip.Reader) (version, hash string) {
	for _, fp := range log4jFingerprints {
		f, err := r.Open(fp.file)
		if err != nil {
			continue
		}
		defer f.Close()

		hash := hashFsFile(f)
		if hash == fp.sha256 {
			if verbose {
				log.Printf("found log4j version %q by fingerprint", fp.version)
			}
			return fp.version, hash
		}
	}

	return Unknown, ""
}

func versionFromJARArchiveMeta(r *zip.Reader) string {
	f, err := r.Open("META-INF/MANIFEST.MF")
	if err != nil {
		return Unknown
	}
	defer f.Close()

	metadata := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ": ", 2)
		if len(parts) == 2 {
			metadata[parts[0]] = parts[1]
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("error reading manifest file: %v", err)
		return Unknown
	}

	var core bool
	if metadata["Implementation-Title"] == ApacheLog4jCore {
		core = true
	}
	if metadata["Specification-Title"] == ApacheLog4jCore {
		core = true
	}
	if metadata["Bundle-Name"] == ApacheLog4jCore {
		core = true
	}
	if metadata["Bundle-SymbolicName"] == "org.apache.logging.log4j.core" {
		core = true
	}
	if !core {
		return Unknown
	}

	candidates := []string{"Implementation-Version", "Bundle-Version"}
	for _, candidate := range candidates {
		if s, ok := metadata[candidate]; ok {
			return s
		}
	}

	return Unknown
}
