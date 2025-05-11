package clients

import (
	"Authentication-Service/internal/domain/dto"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type WebhookHTTPClient struct {
	HTTPClient *http.Client
	Host       string
}

func NewWebhookHTTPClient(host string, timeOut int) *WebhookHTTPClient {
	return &WebhookHTTPClient{HTTPClient: &http.Client{Timeout: time.Duration(timeOut) * time.Second}, Host: host}
}

func (c *WebhookHTTPClient) NotifySuspiciousIp(payload *dto.SuspiciousIpPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.Host+"/notify_ip", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("unexpected response from webhook: %s, %s", resp.Status, resp.Body)
	}

	return nil
}
