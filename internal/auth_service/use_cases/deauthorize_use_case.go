package use_cases

import (
	"Authentication-Service/internal/auth_service"
	"Authentication-Service/internal/auth_service/dto"
	"Authentication-Service/internal/auth_service/services"
)

type DeauthorizeUseCase struct {
	as *services.AuthService
	ts *services.TokenService
}

func NewDeauthorizeUseCase(as *services.AuthService, ts *services.TokenService) *DeauthorizeUseCase {
	return &DeauthorizeUseCase{as: as, ts: ts}
}

func (duc *DeauthorizeUseCase) Execute(tokens *dto.TokenPair) error {
	payload, err := duc.as.PayloadFromAccessToken(tokens.AccessToken)
	if err != nil {
		return err
	}

	refreshToken, err := duc.ts.GetRefreshToken(tokens.RefreshToken)
	if err != nil {
		return err
	}

	if refreshToken.AccessJTI != payload.JTI {
		return auth_service.ErrTokensAreNotAPair
	}

	err = duc.ts.MarkRefreshTokenAsUsed(refreshToken)
	if err != nil {
		return err
	}

	err = duc.as.AddJTIToBlacklist(refreshToken.AccessJTI, payload.ExpiresAt)
	if err != nil {
		return err
	}

	return nil
}
