package domain

import "errors"

var ErrTokenExpired = errors.New("token is expired")
var ErrTokenSignatureInvalid = errors.New("token signature is invalid")
var ErrMultipleTokensFound = errors.New("multiple tokens found")
var ErrTokenNotFound = errors.New("token not found")
var ErrTokenInvalid = errors.New("token is invalid")
var ErrRefreshTokenAlreadyUsed = errors.New("refresh token is already used")
var ErrTokensAreNotAPair = errors.New("tokens are not a pair")
var ErrUserAgentDoesNotMatch = errors.New("user agent does not match")
var ErrTokenBlacklisted = errors.New("token is blacklisted")
