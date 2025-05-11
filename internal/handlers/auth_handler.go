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
//	@Description	Returns token pairs (access + refresh) by GUID
//	@Tags			auth
//	@Produce		json
//	@Param			user_id		query		dto.LoginData		true	"user id"
//	@Success		200			{object}	dto.TokenPair
//	@Failure		400			{object}	string
//	@Failure		401			{object}	string
//	@Failure		500			{object}	string
//	@Router			/login		[post]
func (gh *GinHandler) Login(c *gin.Context) {
	var userId dto.LoginData
	if err := c.ShouldBindQuery(&userId); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid query params, " + err.Error()})
		return
	}

	userData := dto.UserData{
		UserAgent: c.Request.UserAgent(),
		IpAddress: c.ClientIP(),
	}

	tokens, err := gh.linuc.Execute(&userData, userId.UserId)
	if err != nil {
		gh.mapDomainErrToHTTPErr(err, c)
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
func (gh *GinHandler) RefreshTokens(c *gin.Context) {
	var tokens dto.TokenPair
	if err := c.ShouldBindBodyWithJSON(&tokens); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body, " + err.Error()})
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
func (gh *GinHandler) GetUserId(c *gin.Context) {
	userId, exists := c.Get("user_id")
	if exists != true {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user data is missing in request context"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"guid": userId})
}

// Logout godoc
//
//	@Summary		Logout user
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
func (gh *GinHandler) Logout(c *gin.Context) {
	var tokens dto.TokenPair
	if err := c.ShouldBindBodyWithJSON(&tokens); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body, " + err.Error()})
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
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, domain.ErrRefreshTokenAlreadyUsed):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, domain.ErrTokenExpired) ||
		errors.Is(err, domain.ErrTokenInvalid) ||
		errors.Is(err, domain.ErrTokenSignatureInvalid) ||
		errors.Is(err, domain.ErrUserAgentDoesNotMatch) ||
		errors.Is(err, domain.ErrTokenBlacklisted):
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	case errors.Is(err, domain.ErrTokensAreNotAPair):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
}
