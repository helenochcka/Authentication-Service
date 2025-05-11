package services

import (
	"Authentication-Service/internal/domain/dto"
)

type WebhookClient interface {
	NotifySuspiciousIp(payload *dto.SuspiciousIpPayload) error
}

type WebhookService struct {
	wc WebhookClient
}

func NewWebhookService(wc WebhookClient) *WebhookService {
	return &WebhookService{wc: wc}
}

func (ws *WebhookService) NotifySuspiciousIp(userID, oldIp, newIp, userAgent string) error {
	payload := dto.SuspiciousIpPayload{
		UserId:    userID,
		OldIp:     oldIp,
		NewIp:     newIp,
		UserAgent: userAgent,
	}

	err := ws.wc.NotifySuspiciousIp(&payload)
	if err != nil {
		return err
	}

	return nil
}
