package use_cases

import (
	"Authentication-Service/internal/domain"
	"Authentication-Service/internal/domain/dto"
	"Authentication-Service/internal/domain/services"
)

type LogoutUseCase struct {
	as *services.AccessTokenService
	ts *services.RefreshTokenService
}

func NewLogoutUseCase(as *services.AccessTokenService, ts *services.RefreshTokenService) *LogoutUseCase {
	return &LogoutUseCase{as: as, ts: ts}
}

func (luc *LogoutUseCase) Execute(tokens *dto.TokenPair) error {
	at, err := luc.as.GetAccessTokenEntity(tokens.AccessToken)
	if err != nil {
		return err
	}

	rt, err := luc.ts.GetRefreshTokenEntity(tokens.RefreshToken)
	if err != nil {
		return err
	}

	if rt.AccessJTI != at.JTI {
		return domain.ErrTokensAreNotAPair
	}

	err = luc.ts.MarkRefreshTokenAsUsed(rt)
	if err != nil {
		return err
	}

	err = luc.as.AddJTIToBlacklist(rt.AccessJTI, at.ExpiresAt)
	if err != nil {
		return err
	}

	return nil
}
