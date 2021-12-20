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
	"fmt"
	"net/http"

	"github.com/praetorian-inc/log4j-remediation/pkg/types"
)

type ReportClient struct {
	addr   string
	client *http.Client
}

var (
	httpClient = http.DefaultClient
)

func NewReportClient(addr string) *ReportClient {
	return &ReportClient{
		addr:   addr,
		client: httpClient,
	}
}

func (c *ReportClient) HealthCheck() error {
	res, err := c.client.Get(fmt.Sprintf("%s/healthz", c.addr))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("status code %d", res.StatusCode)
	}

	return nil
}

func (c *ReportClient) SendReport(r types.Report) error {
	payloadBuf := new(bytes.Buffer)

	err := json.NewEncoder(payloadBuf).Encode(r)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/logs", c.addr), payloadBuf)
	if err != nil {
		return err
	}

	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("status code %d", res.StatusCode)
	}

	return nil
}
