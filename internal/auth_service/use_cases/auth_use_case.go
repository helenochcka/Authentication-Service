package use_cases

import (
	"Authentication-Service/internal/auth_service"
	"Authentication-Service/internal/auth_service/dto"
	"Authentication-Service/internal/auth_service/services"
)

type AuthUseCase struct {
	as *services.AuthService
}

func NewAuthUseCase(as *services.AuthService) *AuthUseCase {
	return &AuthUseCase{as: as}
}

func (auc *AuthUseCase) Execute(accessToken string) (*dto.AccessTokenPayload, error) {
	tokenPayload, err := auc.as.PayloadFromAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	blacklisted, err := auc.as.CheckIfJTIInBlackList(tokenPayload.JTI)
	if err != nil {
		return nil, err
	}
	if blacklisted {
		return nil, auth_service.ErrTokenBlacklisted
	}

	return tokenPayload, nil
}
