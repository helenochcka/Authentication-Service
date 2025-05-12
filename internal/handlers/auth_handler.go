package handlers

import (
	"Authentication-Service/internal/domain"
	"Authentication-Service/internal/domain/dto"
	"Authentication-Service/internal/domain/use_cases"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
)

type GinHandler struct {
	linuc  *use_cases.LoginUseCase
	ruc    *use_cases.RefreshUseCase
	loutuc *use_cases.LogoutUseCase
}

func NewAuthHandler(
	linuc *use_cases.LoginUseCase,
	ruc *use_cases.RefreshUseCase,
	loutuc *use_cases.LogoutUseCase,
) *GinHandler {
	return &GinHandler{linuc: linuc, ruc: ruc, loutuc: loutuc}
}

// Login godoc
//
//	@Summary		Get token pair
//	@Description	Returns token pair (access + refresh) for user id (GUID)
//	@Tags			auth
//	@Produce		json
//	@Param			user_id		query		dto.UserId		true	"user id"
//	@Success		200			{object}	dto.TokenPair
//	@Failure		401			{object}	HTTPError		"INVALID_QUERY_PARAMS"
//	@Failure		500			{object}	HTTPError		"INTERNAL_SERVER_ERROR"
//	@Router			/login		[post]
func (gh *GinHandler) Login(c *gin.Context) {
	var loginData dto.UserId
	if err := c.ShouldBindQuery(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, HTTPError{Code: "INVALID_QUERY_PARAMS", Message: "invalid query params, " + err.Error()})
		return
	}

	userData := dto.UserData{
		UserAgent: c.Request.UserAgent(),
		IpAddress: c.ClientIP(),
	}

	tokens, err := gh.linuc.Execute(&userData, loginData.UserId)
	if err != nil {
		gh.mapDomainErrToHTTPErr(err, c)
		return
	}

	c.JSON(http.StatusOK, tokens)
}

// RefreshTokens godoc
//
//	@Summary		Update token pair
//	@Description	Returns updated token pair (access + refresh)
//	@Tags			auth
//	@Produce		json
//	@Param			tokens	body		dto.TokenPair	true	"tokens to update"
//	@Success		200		{object}	dto.TokenPair
//	@Failure		400		{object}	HTTPError		"INVALID_JSON_BODY, TOKENS_NOT_PAIR"
//	@Failure		401		{object}	HTTPError		"TOKEN_INVALID, DIFFERENT_USER_AGENT"
//	@Failure		404		{object}	HTTPError		"TOKEN_NOT_FOUND"
//	@Failure		409		{object}	HTTPError		"TOKEN_ALREADY_USED"
//	@Failure		500		{object}	HTTPError		"INTERNAL_SERVER_ERROR"
//	@Router			/tokens/refresh		[put]
func (gh *GinHandler) RefreshTokens(c *gin.Context) {
	var tokens dto.TokenPair
	if err := c.ShouldBindBodyWithJSON(&tokens); err != nil {
		c.JSON(http.StatusBadRequest, HTTPError{Code: "INVALID_JSON_BODY", Message: "invalid json body, " + err.Error()})
		return
	}

	userData := dto.UserData{
		UserAgent: c.Request.UserAgent(),
		IpAddress: c.ClientIP(),
	}

	refreshedTokens, err := gh.ruc.Execute(&userData, &tokens)
	if err != nil {
		gh.mapDomainErrToHTTPErr(err, c)
		return
	}
	c.JSON(http.StatusOK, refreshedTokens)
}

// GetUserId godoc
//
//	@Summary		Get user id
//	@Description	Returns users id (GUID)
//	@Tags			users
//	@Produce		json
//	@Success		200	{object}	dto.UserId
//	@Failure		401	{object}	HTTPError	"TOKEN_INVALID, TOKEN_EXPIRED, TOKEN_BLACKLISTED"
//	@Failure		500	{object}	HTTPError	"INTERNAL_SERVER_ERROR"
//	@Router			/users/guid	[get]
//	@Security		ApiKeyAuth
func (gh *GinHandler) GetUserId(c *gin.Context) {
	userId, exists := c.Get("user_id")
	if exists != true {
		c.JSON(http.StatusInternalServerError, HTTPError{Code: "INTERNAL_SERVER_ERROR", Message: "user id is missing in request context"})
		return
	}

	c.JSON(http.StatusOK, dto.UserId{UserId: userId.(string)})
}

// Logout godoc
//
//	@Summary		Logout user
//	@Description	Invalidate tokens
//	@Tags			auth
//	@Produce		json
//	@Param			tokens	body		dto.TokenPair	true	"tokens to invalidate"
//	@Success		204
//	@Failure		400		{object}	HTTPError		"INVALID_JSON_BODY, TOKENS_NOT_PAIR"
//	@Failure		401		{object}	HTTPError		"TOKEN_EXPIRED, TOKEN_INVALID, TOKEN_BLACKLISTED"
//	@Failure		404		{object}	HTTPError		"TOKEN_NOT_FOUND"
//	@Failure		409		{object}	HTTPError		"TOKEN_ALREADY_USED"
//	@Failure		500		{object}	HTTPError		"INTERNAL_SERVER_ERROR"
//	@Router			/logout		[post]
func (gh *GinHandler) Logout(c *gin.Context) {
	var tokens dto.TokenPair
	if err := c.ShouldBindBodyWithJSON(&tokens); err != nil {
		c.JSON(http.StatusBadRequest, HTTPError{Code: "INVALID_JSON_BODY", Message: "invalid json body, " + err.Error()})
		return
	}
	err := gh.loutuc.Execute(&tokens)
	if err != nil {
		gh.mapDomainErrToHTTPErr(err, c)
		return
	}
	c.JSON(http.StatusNoContent, gin.H{})
}

func (gh *GinHandler) mapDomainErrToHTTPErr(err error, c *gin.Context) {
	switch {
	case errors.Is(err, domain.ErrTokenNotFound):
		c.JSON(http.StatusNotFound, HTTPError{Code: "TOKEN_NOT_FOUND", Message: "refresh token not found"})
	case errors.Is(err, domain.ErrRefreshTokenAlreadyUsed):
		c.JSON(http.StatusConflict, HTTPError{Code: "TOKEN_ALREADY_USED", Message: "refresh token is already used"})
	case errors.Is(err, domain.ErrTokenExpired):
		c.JSON(http.StatusUnauthorized, HTTPError{Code: "TOKEN_EXPIRED", Message: "access token is expired"})
	case errors.Is(err, domain.ErrTokenInvalid):
		c.JSON(http.StatusUnauthorized, HTTPError{Code: "TOKEN_INVALID", Message: "access token is invalid"})
	case errors.Is(err, domain.ErrUserAgentDoesNotMatch):
		c.JSON(http.StatusUnauthorized, HTTPError{Code: "DIFFERENT_USER_AGENT", Message: "user agent does not match"})
	case errors.Is(err, domain.ErrTokenBlacklisted):
		c.JSON(http.StatusUnauthorized, HTTPError{Code: "TOKEN_BLACKLISTED", Message: "access token is blacklisted"})
	case errors.Is(err, domain.ErrTokensAreNotAPair):
		c.JSON(http.StatusBadRequest, HTTPError{Code: "TOKENS_NOT_PAIR", Message: "access and refresh tokens is not a pair"})
	default:
		c.JSON(http.StatusInternalServerError, HTTPError{Code: "INTERNAL_SERVER_ERROR", Message: err.Error()})
	}
}
