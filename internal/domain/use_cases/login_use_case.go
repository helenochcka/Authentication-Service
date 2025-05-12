package use_cases

import (
	"Authentication-Service/internal/domain/dto"
	"Authentication-Service/internal/domain/services"
)

type LoginUseCase struct {
	as *services.AccessTokenService
	ts *services.RefreshTokenService
}

func NewLoginUseCase(
	as *services.AccessTokenService,
	ts *services.RefreshTokenService,
) *LoginUseCase {
	return &LoginUseCase{as: as, ts: ts}
}

func (luc *LoginUseCase) Execute(userData *dto.UserData, userId string) (*dto.TokenPair, error) {
	at, err := luc.as.GenerateAccessToken(userId)
	if err != nil {
		return nil, err
	}

	atObj, err := luc.as.GetAccessTokenEntity(*at)
	if err != nil {
		return nil, err
	}

	rt, err := luc.ts.GenerateRefreshToken(userData, atObj.JTI, userId)
	if err != nil {
		return nil, err
	}

	return &dto.TokenPair{AccessToken: *at, RefreshToken: *rt}, nil
}
