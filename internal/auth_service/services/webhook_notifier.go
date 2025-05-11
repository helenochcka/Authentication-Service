package services

import (
	"Authentication-Service/internal/auth_service/dto"
)

type Client interface {
	Send(payload *dto.SuspiciousIpPayload) error
}

type WebhookNotifier struct {
	c          Client
	webhookURL string
}

func NewWebhookNotifier(webhookURL string, c Client) *WebhookNotifier {
	return &WebhookNotifier{
		webhookURL: webhookURL,
		c:          c,
	}
}

func (w *WebhookNotifier) NotifySuspiciousIp(userID, oldIp, newIp, userAgent string) error {
	payload := dto.SuspiciousIpPayload{
		UserId:    userID,
		OldIp:     oldIp,
		NewIp:     newIp,
		UserAgent: userAgent,
	}

	err := w.c.Send(&payload)
	if err != nil {
		return err
	}

	return nil
}
