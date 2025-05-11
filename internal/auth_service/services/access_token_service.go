package services

import (
	"Authentication-Service/internal/auth_service"
	"Authentication-Service/internal/auth_service/dto"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

type JTIRepo interface {
	GetOne(jti string) (bool, error)
	Insert(jti string, expiresAt int64) error
}

type AuthService struct {
	SecretKey    string
	TokenExpTime int
	jr           JTIRepo
}

func NewAuthService(secretKey string, tokenExpTime int, jr JTIRepo) *AuthService {
	return &AuthService{SecretKey: secretKey, TokenExpTime: tokenExpTime, jr: jr}
}

func (as *AuthService) GenerateAccessToken(userId string) (*string, error) {
	payload := jwt.MapClaims{
		"id":  userId,
		"exp": time.Now().Add(time.Minute * time.Duration(as.TokenExpTime)).Unix(),
		"jti": uuid.New().String(),
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, payload).SignedString([]byte(as.SecretKey))
	if err != nil {
		return nil, err
	}

	return &accessToken, nil
}

func (as *AuthService) PayloadFromAccessToken(tokenString string) (*dto.AccessTokenPayload, error) {
	accessToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(as.SecretKey), nil
	})

	if err != nil {
		return nil, as.mapJWTErrToAuthErr(err)
	}

	payload := accessToken.Claims.(jwt.MapClaims)
	userId := payload["id"].(string)
	exp := int64(payload["exp"].(float64))
	jti := payload["jti"].(string)

	return &dto.AccessTokenPayload{UserId: userId, ExpiresAt: exp, JTI: jti}, nil
}

func (as *AuthService) PayloadFromExpiredAccessToken(tokenString string) (*dto.AccessTokenPayload, error) {
	accessToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(as.SecretKey), nil
	})
	if err == nil || errors.Is(as.mapJWTErrToAuthErr(err), auth_service.ErrTokenExpired) {
		payload := accessToken.Claims.(jwt.MapClaims)
		userId := payload["id"].(string)
		exp := int64(payload["exp"].(float64))
		jti := payload["jti"].(string)

		return &dto.AccessTokenPayload{UserId: userId, ExpiresAt: exp, JTI: jti}, nil
	}

	return nil, as.mapJWTErrToAuthErr(err)
}

func (as *AuthService) AddJTIToBlacklist(jti string, accessExpiredAt int64) error {
	err := as.jr.Insert(jti, accessExpiredAt)
	if err != nil {
		return err
	}
	return nil
}

func (as *AuthService) CheckIfJTIInBlackList(jti string) (bool, error) {
	blacklisted, err := as.jr.GetOne(jti)
	if err != nil {
		return false, err
	}
	return blacklisted, nil
}

func (as *AuthService) mapJWTErrToAuthErr(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return auth_service.ErrTokenExpired
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return auth_service.ErrTokenSignatureInvalid
	default:
		return err
	}
}
