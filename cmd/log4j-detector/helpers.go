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
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
)

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "error"
	}
	defer f.Close()

	return hashFsFile(f)
}

func hashFsFile(f fs.File) string {
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "error"
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

func fileExists(path string) bool {
	info, err := os.Lstat(path)

	switch {
	case os.IsNotExist(err):
		// path does not exist
		return false
	case err != nil:
		// return true since error is not of type IsNotExist
		return true
	default:
		// return true only if this is a file
		return info.Mode().IsRegular()
	}
}
