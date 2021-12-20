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

package slack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/praetorian-inc/log4j-remediation/pkg/types"
)

type WebhookRequest struct {
	Blocks []Block `json:"blocks"`
}
type Block struct {
	Type     string    `json:"type"`
	Elements []Element `json:"elements,omitempty"`
	Fields   []Element `json:"fields"`
	Text     *Element  `json:"text"`
}

type Element struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

func generateWebhookRequest(vuln types.Vulnerability) WebhookRequest {
	return WebhookRequest{
		Blocks: []Block{
			{
				Type: "header",
				Text: &Element{
					Type: "plain_text",
					Text: "Log4J Detector Alert",
				},
			},
			{
				Type: "section",
				Text: &Element{
					Type: "mrkdwn",
					Text: fmt.Sprintf(">*Host:* _%s_\n>*Version:* _%s_\n>*Process:* _%s (PID %d)_\n>*Jar File:* ```%s```\n>*SHA256:* ```%s```", // nolint:lll
						vuln.Hostname, vuln.Version, vuln.ProcessName, vuln.ProcessID, vuln.Path, vuln.SHA256),
				},
			},
		},
	}
}

func Notify(webhookURL string, vuln types.Vulnerability) error {
	body, _ := json.Marshal(generateWebhookRequest(vuln))
	log.Printf("sending: %s", body)
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("status code %d from slack", resp.StatusCode)
	}
	return nil
}
