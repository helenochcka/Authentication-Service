package handlers

import (
	"Authentication-Service/internal/auth_service"
	"Authentication-Service/internal/auth_service/dto"
	"Authentication-Service/internal/auth_service/use_cases"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
)

type AuthHandler struct {
	luc *use_cases.LoginUseCase
	ruc *use_cases.RefreshUseCase
	duc *use_cases.DeauthorizeUseCase
}

func NewAuthHandler(
	luc *use_cases.LoginUseCase,
	ruc *use_cases.RefreshUseCase,
	duc *use_cases.DeauthorizeUseCase,
) *AuthHandler {
	return &AuthHandler{luc: luc, ruc: ruc, duc: duc}
}

// Login godoc
//
//	@Summary		Get token pair
//	@Description	Returns token pairs (access + refresh) by GUID
//	@Tags			auth
//	@Produce		json
//	@Param			user_id		query		dto.UserId		true	"user id"
//	@Success		200			{object}	dto.TokenPair
//	@Failure		400			{object}	string
//	@Failure		401			{object}	string
//	@Failure		500			{object}	string
//	@Router			/login		[post]
func (ah *AuthHandler) Login(c *gin.Context) {
	var userId dto.UserId
	if err := c.ShouldBindQuery(&userId); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid query params, " + err.Error()})
		return
	}

	userAgent, exists := c.Get("user_agent")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user agent is missing in request context"})
		return
	}

	ipAddress, exists := c.Get("ip_address")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ip address is missing in request context"})
		return
	}

	userData := dto.UserData{
		UserAgent: userAgent.(string),
		IpAddress: ipAddress.(string),
	}

	tokens, err := ah.luc.Execute(&userData, userId.UserId)
	if err != nil {
		ah.mapUsersErrToHTTPErr(err, c)
		return
	}

	c.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

// RefreshTokens godoc
//
//	@Summary		Update a pair of tokens
//	@Description	Returns updated token pairs (access + refresh)
//	@Tags			auth
//	@Produce		json
//	@Param			tokens	body		dto.TokenPair	true	"tokens for update"
//	@Success		200		{object}	dto.TokenPair
//	@Failure		400		{object}	string
//	@Failure		401			{object}	string
//	@Failure		404			{object}	string
//	@Failure		409			{object}	string
//	@Failure		500			{object}	string
//	@Router			/tokens/refresh		[put]
func (ah *AuthHandler) RefreshTokens(c *gin.Context) {
	var tokens dto.TokenPair
	if err := c.ShouldBindBodyWithJSON(&tokens); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body, " + err.Error()})
		return
	}
	userAgent, exists := c.Get("user_agent")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user agent is missing in request context"})
		return
	}

	ipAddress, exists := c.Get("ip_address")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ip address is missing in request context"})
		return
	}

	userData := dto.UserData{
		UserAgent: userAgent.(string),
		IpAddress: ipAddress.(string),
	}

	refreshedTokens, err := ah.ruc.Execute(&userData, &tokens)
	if err != nil {
		ah.mapUsersErrToHTTPErr(err, c)
		return
	}
	c.JSON(http.StatusOK, gin.H{"tokens": refreshedTokens})
}

// GetUserId godoc
//
//	@Summary		Get user id (GUID)
//	@Description	Returns user's id (GUID)
//	@Tags			users
//	@Produce		json
//	@Success		200			{object}	string
//	@Failure		401			{object}	string
//	@Failure		403			{object}	string
//	@Failure		500			{object}	string
//	@Router			/users/guid		[get]
//	@Security		ApiKeyAuth
func (ah *AuthHandler) GetUserId(c *gin.Context) {
	userId, exists := c.Get("user_id")
	if exists != true {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user data is missing in request context"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"guid": userId})
}

// Logout godoc
//
//	@Summary		Deauthorize user
//	@Description	Invalidate tokens
//	@Tags			auth
//	@Produce		json
//	@Param			tokens		body		dto.TokenPair	true	"tokens for invalidate"
//	@Success		200			{object}	string
//	@Failure		400			{object}	string
//	@Failure		401			{object}	string
//	@Failure		404			{object}	string
//	@Failure		409			{object}	string
//	@Failure		500			{object}	string
//	@Router			/logout		[post]
func (ah *AuthHandler) Logout(c *gin.Context) {
	var tokens dto.TokenPair
	if err := c.ShouldBindBodyWithJSON(&tokens); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body, " + err.Error()})
		return
	}
	err := ah.duc.Execute(&tokens)
	if err != nil {
		ah.mapUsersErrToHTTPErr(err, c)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deauthorized"})
}

func (ah *AuthHandler) mapUsersErrToHTTPErr(err error, c *gin.Context) {
	switch {
	case errors.Is(err, auth_service.ErrTokenNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, auth_service.ErrMultipleTokensFound):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, auth_service.ErrTokenExpired) ||
		errors.Is(err, auth_service.ErrTokenInvalid) ||
		errors.Is(err, auth_service.ErrTokenSignatureInvalid):
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	case errors.Is(err, auth_service.ErrRefreshTokenAlreadyUsed) ||
		errors.Is(err, auth_service.ErrTokensAreNotAPair) ||
		errors.Is(err, auth_service.ErrUserAgentDoesNotMatch) ||
		errors.Is(err, auth_service.ErrTokenBlacklisted):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
}
