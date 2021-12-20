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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/praetorian-inc/log4j-remediation/pkg/build"
	"github.com/praetorian-inc/log4j-remediation/pkg/log4j"
	"github.com/praetorian-inc/log4j-remediation/pkg/slack"
	"github.com/praetorian-inc/log4j-remediation/pkg/types"
	"github.com/praetorian-inc/log4j-remediation/pkg/webhook"
	"github.com/praetorian-inc/log4j-remediation/www"
)

var (
	printversion       bool
	listenAddr         string
	certPath           string
	keyPath            string
	binaryDir          string
	logDir             string
	slackWebhook       string
	genericWebhook     string
	genericWebhookAuth string
	archive            io.WriteCloser
)

func main() {
	flag.StringVar(&listenAddr, "addr", ":8443", "listen on address")
	flag.StringVar(&binaryDir, "bin-dir", "dist/", "directory containing static binaries")
	flag.StringVar(&logDir, "log-dir", ".", "directory to write logs to")
	flag.StringVar(&certPath, "cert", "", "path to TLS cert")
	flag.StringVar(&keyPath, "key", "", "path to TLS key")
	flag.StringVar(&slackWebhook, "slack-webhook", "", "optional slack webhook to notify")
	flag.StringVar(&genericWebhook, "generic-webhook", "", "optional generic webhook to notify")
	flag.StringVar(&genericWebhookAuth, "generic-webhook-auth", "", "optional generic webhook auth key")
	flag.BoolVar(&printversion, "v", false, "prints current version")
	flag.Parse()
	log.SetOutput(os.Stderr)

	if printversion {
		fmt.Printf("report-server version %s", build.Version)
		return
	}

	var err error
	archive, err = os.OpenFile(logDir+"/log4j-remediation.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer archive.Close()

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {})
	http.HandleFunc("/logs", LogHandler)
	http.Handle("/bin/", http.StripPrefix("/bin",
		http.FileServer(http.Dir(binaryDir))),
	)
	http.Handle("/", http.FileServer(http.FS(www.Content)))

	log.Printf("listening on %s", listenAddr)

	if certPath != "" && keyPath != "" {
		err = http.ListenAndServeTLS(listenAddr, certPath, keyPath, nil)
	} else {
		err = http.ListenAndServe(listenAddr, nil)
	}
	if err != nil {
		log.Fatalf("failed to serve: %s", err) // nolint:gocritic
	}
}

func LogHandler(w http.ResponseWriter, r *http.Request) {
	var report types.Report

	log.Printf("%s: received report", r.RemoteAddr)

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "trouble reading json body", 500)
		return
	}

	err = json.Unmarshal(b, &report)
	if err != nil {
		http.Error(w, "improperly formatted report", 500)
		return
	}

	report.Vulnerabilities = log4j.DetectVulnerabilities(report)
	if genericWebhook != "" {
		err = webhook.Notify(genericWebhook, genericWebhookAuth, report)
		if err != nil {
			log.Printf("failed to notify: %s", err)
		}
	}

	for _, vuln := range report.Vulnerabilities {
		log.Printf("%s using log4j %s in process [%d] %s at %s",
			vuln.Hostname, vuln.Version, vuln.ProcessID, vuln.ProcessName, vuln.Path)

		if slackWebhook != "" {
			err = slack.Notify(slackWebhook, vuln)
			if err != nil {
				log.Printf("error talking to slack: %s", err)
			}
		}
	}

	rawLog, err := json.Marshal(report)
	if err != nil {
		http.Error(w, "couldn't marshal report to json", 500)
		return
	}

	fmt.Fprintf(archive, "%s\n", rawLog)
}
