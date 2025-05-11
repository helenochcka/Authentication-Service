package middlewares

import (
	"Authentication-Service/internal/auth_service"
	"Authentication-Service/internal/auth_service/use_cases"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
)

type AuthMiddleware struct {
	auc *use_cases.AuthUseCase
}

func NewAuthMiddleware(
	auc *use_cases.AuthUseCase,
) *AuthMiddleware {
	return &AuthMiddleware{
		auc: auc,
	}
}

func (am *AuthMiddleware) AuthUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken := c.GetHeader("Authorization")
		payload, err := am.auc.Execute(accessToken)
		if err != nil {
			mapUsersErrToHTTPErr(err, c)
			c.Abort()
			return
		}

		c.Set("user_id", payload.UserId)

		c.Next()
	}
}

func (am *AuthMiddleware) GetHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		userAgent := c.Request.UserAgent()
		ipAddress := c.ClientIP()

		c.Set("user_agent", userAgent)
		c.Set("ip_address", ipAddress)

		c.Next()
	}
}

func mapUsersErrToHTTPErr(err error, c *gin.Context) {
	switch {
	case errors.Is(err, auth_service.ErrTokenExpired) ||
		errors.Is(err, auth_service.ErrTokenSignatureInvalid):
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	case errors.Is(err, auth_service.ErrTokenBlacklisted):
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
}
