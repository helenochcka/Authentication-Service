package use_cases

import (
	"Authentication-Service/internal/domain"
	"Authentication-Service/internal/domain/dto"
	"Authentication-Service/internal/domain/services"
	"errors"
)

type RefreshUseCase struct {
	as *services.AccessTokenService
	ts *services.RefreshTokenService
	wn *services.WebhookService
}

func NewRefreshUseCase(
	as *services.AccessTokenService,
	ts *services.RefreshTokenService,
	wn *services.WebhookService,
) *RefreshUseCase {
	return &RefreshUseCase{as: as, ts: ts, wn: wn}
}

func (ruc *RefreshUseCase) Execute(userData *dto.UserData, tokens *dto.TokenPair) (*dto.TokenPair, error) {
	refreshToken, err := ruc.ts.GetRefreshTokenEntity(tokens.RefreshToken)
	if err != nil {
		return nil, err
	}

	payload, err := ruc.as.PayloadFromAccessToken(tokens.AccessToken)
	if errors.Is(err, domain.ErrTokenExpired) {
		payload, err = ruc.as.PayloadFromExpiredAccessToken(tokens.AccessToken)
		if err != nil {
			return nil, err
		}
		if payload.JTI != refreshToken.AccessJTI {
			return nil, domain.ErrTokensAreNotAPair
		}
	} else if err == nil {
		if payload.JTI != refreshToken.AccessJTI {
			return nil, domain.ErrTokensAreNotAPair
		}
		err = ruc.as.AddJTIToBlacklist(refreshToken.AccessJTI, payload.ExpiresAt)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}

	err = ruc.ts.MarkRefreshTokenAsUsed(refreshToken)
	if err != nil {
		return nil, err
	}

	if userData.UserAgent != refreshToken.UserAgent {
		return nil, domain.ErrUserAgentDoesNotMatch
	}

	if userData.IpAddress != refreshToken.IpAddress {
		err = ruc.wn.NotifySuspiciousIp(
			refreshToken.UserId,
			userData.IpAddress,
			refreshToken.IpAddress,
			refreshToken.UserAgent)
		if err != nil {
			return nil, err
		}
		if err = ruc.ts.ChangeIpAddress(refreshToken, userData.IpAddress); err != nil {
			return nil, err
		}
	}

	at, err := ruc.as.GenerateAccessToken(payload.UserId)
	if err != nil {
		return nil, err
	}

	payload, err = ruc.as.PayloadFromAccessToken(*at)
	if err != nil {
		return nil, err
	}

	rt, err := ruc.ts.GenerateRefreshToken(userData, payload.JTI, payload.UserId)
	if err != nil {
		return nil, err
	}

	return &dto.TokenPair{AccessToken: *at, RefreshToken: *rt}, nil
}
