package services

import (
	"Authentication-Service/internal/auth_service"
	"Authentication-Service/internal/auth_service/dto"
	"Authentication-Service/internal/auth_service/entity"
	"Authentication-Service/internal/repositories"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type TokenRepo interface {
	GetOne(tokenSHA string) (*entity.RefreshToken, error)
	Insert(token *entity.RefreshToken) error
	Update(token *entity.RefreshToken) error
}

type TokenService struct {
	tr           TokenRepo
	TokenExpTime int
	SecretKey    string
}

func NewTokenService(tr TokenRepo, TokenExpTime int, SecretKey string) *TokenService {
	return &TokenService{tr: tr, TokenExpTime: TokenExpTime, SecretKey: SecretKey}
}

func (ts *TokenService) GetRefreshToken(stringRawToken string) (*entity.RefreshToken, error) {
	rawToken, err := base64.StdEncoding.DecodeString(stringRawToken)
	if err != nil {
		return nil, err
	}

	tokenSha := sha256.Sum256(rawToken)
	stringTokenSha := base64.StdEncoding.EncodeToString(tokenSha[:])

	rt, err := ts.tr.GetOne(stringTokenSha)
	if err != nil {
		return nil, ts.mapJWTErrToAuthErr(err)
	}

	if bcrypt.CompareHashAndPassword([]byte(rt.TokenBcrypt), rawToken) != nil {
		return nil, auth_service.ErrTokenInvalid
	}

	return rt, nil
}

func (ts *TokenService) GenerateRefreshToken(userData *dto.UserData, accessJTI, userId string) (*string, error) {
	rawToken := ts.generateRawToken()
	tokenSha := sha256.Sum256(rawToken)
	stringTokenSha := base64.StdEncoding.EncodeToString(tokenSha[:])
	tokenBcrypt, err := bcrypt.GenerateFromPassword(rawToken, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	rt := &entity.RefreshToken{
		TokenSha:    stringTokenSha,
		UserId:      userId,
		TokenBcrypt: string(tokenBcrypt),
		ExpiresAt:   time.Now().Add(time.Hour * time.Duration(ts.TokenExpTime)),
		Used:        false,
		UserAgent:   userData.UserAgent,
		IpAddress:   userData.IpAddress,
		AccessJTI:   accessJTI,
	}

	if err = ts.tr.Insert(rt); err != nil {
		return nil, err
	}

	stringRawToken := base64.StdEncoding.EncodeToString(rawToken)

	return &stringRawToken, err
}

func (ts *TokenService) MarkRefreshTokenAsUsed(rt *entity.RefreshToken) error {
	if rt.Used {
		return auth_service.ErrRefreshTokenAlreadyUsed
	}
	if rt.ExpiresAt.Before(time.Now()) {
		return auth_service.ErrTokenExpired
	}
	rt.Used = true
	if err := ts.tr.Update(rt); err != nil {
		return err
	}

	return nil
}

func (ts *TokenService) ChangeIpAddress(rt *entity.RefreshToken, ipAddress string) error {
	rt.IpAddress = ipAddress
	if err := ts.tr.Update(rt); err != nil {
		return err
	}
	return nil
}

func (ts *TokenService) mapJWTErrToAuthErr(err error) error {
	switch {
	case errors.Is(err, repositories.ErrMultipleRecFound):
		return auth_service.ErrMultipleTokensFound
	case errors.Is(err, repositories.ErrRecNotFound):
		return auth_service.ErrTokenNotFound
	default:
		return err
	}
}

func (ts *TokenService) generateRawToken() []byte {
	const size = 32
	b := make([]byte, size)
	rand.Read(b)
	return b
}
