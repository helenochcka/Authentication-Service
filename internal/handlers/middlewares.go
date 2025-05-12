package handlers

import (
	"Authentication-Service/internal/domain"
	"Authentication-Service/internal/domain/use_cases"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
)

type AuthMiddleware struct {
	auc *use_cases.AuthUseCase
}

func NewAuthMiddleware(auc *use_cases.AuthUseCase) *AuthMiddleware {
	return &AuthMiddleware{auc: auc}
}

func (am *AuthMiddleware) AuthUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		accessTokenString := c.GetHeader("Authorization")
		at, err := am.auc.Execute(accessTokenString)
		if err != nil {
			mapDomainErrToHTTPErr(err, c)
			c.Abort()
			return
		}

		c.Set("user_id", at.UserId)

		c.Next()
	}
}

func mapDomainErrToHTTPErr(err error, c *gin.Context) {
	switch {
	case errors.Is(err, domain.ErrTokenExpired):
		c.JSON(http.StatusUnauthorized, HTTPError{Code: "TOKEN_EXPIRED", Message: "access token is expired"})
	case errors.Is(err, domain.ErrTokenBlacklisted):
		c.JSON(http.StatusUnauthorized, HTTPError{Code: "TOKEN_BLACKLISTED", Message: "access token is blacklisted"})
	case errors.Is(err, domain.ErrTokenInvalid):
		c.JSON(http.StatusUnauthorized, HTTPError{Code: "TOKEN_INVALID", Message: "access token is invalid"})
	default:
		c.JSON(http.StatusInternalServerError, HTTPError{Code: "INTERNAL_SERVER_ERROR", Message: err.Error()})
	}
}
