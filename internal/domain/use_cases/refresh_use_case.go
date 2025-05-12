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

	accessToken, err := ruc.as.GetAccessTokenEntity(tokens.AccessToken)
	if err != nil && !errors.Is(err, domain.ErrTokenExpired) {
		return nil, err
	}
	if accessToken.JTI != refreshToken.AccessJTI {
		return nil, domain.ErrTokensAreNotAPair
	}

	if err == nil {
		err = ruc.as.AddJTIToBlacklist(refreshToken.AccessJTI, accessToken.ExpiresAt)
		if err != nil {
			return nil, err
		}
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

	at, err := ruc.as.GenerateAccessToken(accessToken.UserId)
	if err != nil {
		return nil, err
	}

	accessToken, err = ruc.as.GetAccessTokenEntity(*at)
	if err != nil {
		return nil, err
	}

	rt, err := ruc.ts.GenerateRefreshToken(userData, accessToken.JTI, accessToken.UserId)
	if err != nil {
		return nil, err
	}

	return &dto.TokenPair{AccessToken: *at, RefreshToken: *rt}, nil
}
