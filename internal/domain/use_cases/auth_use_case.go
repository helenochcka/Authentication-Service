package use_cases

import (
	"Authentication-Service/internal/domain"
	"Authentication-Service/internal/domain/entities"
	"Authentication-Service/internal/domain/services"
)

type AuthUseCase struct {
	ats *services.AccessTokenService
}

func NewAuthUseCase(ats *services.AccessTokenService) *AuthUseCase {
	return &AuthUseCase{ats: ats}
}

func (auc *AuthUseCase) Execute(accessToken string) (*entities.AccessToken, error) {
	at, err := auc.ats.GetAccessTokenEntity(accessToken)
	if err != nil {
		return nil, err
	}

	blacklisted, err := auc.ats.IsJTIBlacklisted(at.JTI)
	if err != nil {
		return nil, err
	}
	if blacklisted {
		return nil, domain.ErrTokenBlacklisted
	}

	return at, nil
}
