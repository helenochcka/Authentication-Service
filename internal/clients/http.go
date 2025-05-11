package clients

import (
	"Authentication-Service/internal/auth_service/dto"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func ProduceHTTPClient(url string, timeOut int) *Client {
	return NewClient(&http.Client{Timeout: time.Duration(timeOut) * time.Second}, url)
}

type Client struct {
	HTTPClient *http.Client
	URL        string
}

func NewClient(httpClient *http.Client, url string) *Client {
	return &Client{HTTPClient: httpClient, URL: url}
}

func (c *Client) Send(payload *dto.SuspiciousIpPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.URL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status: %s", resp.Status)
	}

	return nil
}
