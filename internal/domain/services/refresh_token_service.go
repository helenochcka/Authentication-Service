package services

import (
	"Authentication-Service/internal/domain"
	"Authentication-Service/internal/domain/dto"
	"Authentication-Service/internal/domain/entities"
	"Authentication-Service/internal/repositories"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type RefreshTokenRepo interface {
	GetOne(tokenSHA string) (*entities.RefreshToken, error)
	Insert(token *entities.RefreshToken) error
	Update(token *entities.RefreshToken) error
}

type RefreshTokenService struct {
	tr           RefreshTokenRepo
	tokenExpTime int
}

func NewRefreshTokenService(tr RefreshTokenRepo, TokenExpTime int) *RefreshTokenService {
	return &RefreshTokenService{tr: tr, tokenExpTime: TokenExpTime}
}

func (rts *RefreshTokenService) GetRefreshTokenEntity(token string) (*entities.RefreshToken, error) {
	tokenBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	tokenShaBytes := sha256.Sum256(tokenBytes)
	tokenSha := base64.StdEncoding.EncodeToString(tokenShaBytes[:])

	rt, err := rts.tr.GetOne(tokenSha)
	if err != nil {
		return nil, rts.mapRepoErrToDomainErr(err)
	}

	if bcrypt.CompareHashAndPassword([]byte(rt.TokenBcrypt), tokenBytes) != nil {
		return nil, domain.ErrTokenInvalid
	}

	return rt, nil
}

func (rts *RefreshTokenService) GenerateRefreshToken(userData *dto.UserData, accessJTI, userId string) (*string, error) {
	tokenBytes := rts.generateRawToken()
	tokenShaBytes := sha256.Sum256(tokenBytes)
	tokenSha := base64.StdEncoding.EncodeToString(tokenShaBytes[:])
	tokenBcryptBytes, err := bcrypt.GenerateFromPassword(tokenBytes, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	rt := &entities.RefreshToken{
		TokenSha:    tokenSha,
		UserId:      userId,
		TokenBcrypt: string(tokenBcryptBytes),
		ExpiresAt:   time.Now().Add(time.Hour * 24 * time.Duration(rts.tokenExpTime)),
		Used:        false,
		UserAgent:   userData.UserAgent,
		IpAddress:   userData.IpAddress,
		AccessJTI:   accessJTI,
	}

	if err = rts.tr.Insert(rt); err != nil {
		return nil, err
	}

	token := base64.StdEncoding.EncodeToString(tokenBytes)

	return &token, err
}

func (rts *RefreshTokenService) MarkRefreshTokenAsUsed(rt *entities.RefreshToken) error {
	if rt.Used {
		return domain.ErrRefreshTokenAlreadyUsed
	}
	if rt.ExpiresAt.Before(time.Now()) {
		return domain.ErrTokenExpired
	}
	rt.Used = true
	if err := rts.tr.Update(rt); err != nil {
		return err
	}

	return nil
}

func (rts *RefreshTokenService) ChangeIpAddress(rt *entities.RefreshToken, ipAddress string) error {
	rt.IpAddress = ipAddress
	if err := rts.tr.Update(rt); err != nil {
		return err
	}
	return nil
}

func (rts *RefreshTokenService) mapRepoErrToDomainErr(err error) error {
	switch {
	case errors.Is(err, repositories.ErrMultipleRecFound):
		return domain.ErrMultipleTokensFound
	case errors.Is(err, repositories.ErrRecNotFound):
		return domain.ErrTokenNotFound
	default:
		return err
	}
}

func (rts *RefreshTokenService) generateRawToken() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}
