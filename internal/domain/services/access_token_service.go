package services

import (
	"Authentication-Service/internal/domain"
	"Authentication-Service/internal/domain/entities"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

type JTIRepo interface {
	Exists(jti string) (bool, error)
	Set(jti string, expiresAt int64) error
}

type AccessTokenService struct {
	secretKey    string
	tokenExpTime int
	jtir         JTIRepo
}

func NewAccessTokenService(secretKey string, tokenExpTime int, jtir JTIRepo) *AccessTokenService {
	return &AccessTokenService{secretKey: secretKey, tokenExpTime: tokenExpTime, jtir: jtir}
}

func (ats *AccessTokenService) GenerateAccessToken(userId string) (*string, error) {
	payload := jwt.MapClaims{
		"id":  userId,
		"exp": time.Now().Add(time.Minute * time.Duration(ats.tokenExpTime)).Unix(),
		"jti": uuid.New().String(),
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, payload).SignedString([]byte(ats.secretKey))
	if err != nil {
		return nil, err
	}

	return &accessToken, nil
}

func (ats *AccessTokenService) PayloadFromAccessToken(token string) (*entities.AccessToken, error) {
	tokenObj, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(ats.secretKey), nil
	})

	if err != nil {
		return nil, ats.mapJWTErrToDomainErr(err)
	}

	payload := tokenObj.Claims.(jwt.MapClaims)
	userId := payload["id"].(string)
	exp := int64(payload["exp"].(float64))
	jti := payload["jti"].(string)

	return &entities.AccessToken{UserId: userId, ExpiresAt: exp, JTI: jti}, nil
}

func (ats *AccessTokenService) PayloadFromExpiredAccessToken(token string) (*entities.AccessToken, error) {
	tokenObj, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(ats.secretKey), nil
	})
	if err == nil || errors.Is(ats.mapJWTErrToDomainErr(err), domain.ErrTokenExpired) {
		payload := tokenObj.Claims.(jwt.MapClaims)
		userId := payload["id"].(string)
		exp := int64(payload["exp"].(float64))
		jti := payload["jti"].(string)

		return &entities.AccessToken{UserId: userId, ExpiresAt: exp, JTI: jti}, nil
	}

	return nil, ats.mapJWTErrToDomainErr(err)
}

func (ats *AccessTokenService) AddJTIToBlacklist(jti string, expiredAt int64) error {
	err := ats.jtir.Set(jti, expiredAt)
	if err != nil {
		return err
	}
	return nil
}

func (ats *AccessTokenService) IsJTIBlacklisted(jti string) (bool, error) {
	blacklisted, err := ats.jtir.Exists(jti)
	if err != nil {
		return false, err
	}
	return blacklisted, nil
}

func (ats *AccessTokenService) mapJWTErrToDomainErr(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return domain.ErrTokenExpired
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return domain.ErrTokenSignatureInvalid
	default:
		return err
	}
}
