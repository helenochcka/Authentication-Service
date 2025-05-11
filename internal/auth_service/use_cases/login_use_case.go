package use_cases

import (
	"Authentication-Service/internal/auth_service/dto"
	"Authentication-Service/internal/auth_service/services"
)

type LoginUseCase struct {
	as *services.AuthService
	ts *services.TokenService
}

func NewLoginUseCase(
	as *services.AuthService,
	ts *services.TokenService,
) *LoginUseCase {
	return &LoginUseCase{as: as, ts: ts}
}

func (luc *LoginUseCase) Execute(userData *dto.UserData, userId string) (*dto.TokenPair, error) {
	accessToken, err := luc.as.GenerateAccessToken(userId)
	if err != nil {
		return nil, err
	}

	payload, err := luc.as.PayloadFromExpiredAccessToken(*accessToken)
	if err != nil {
		return nil, err
	}

	refreshToken, err := luc.ts.GenerateRefreshToken(userData, payload.JTI, userId)
	if err != nil {
		return nil, err
	}

	return &dto.TokenPair{AccessToken: *accessToken, RefreshToken: *refreshToken}, nil
}
