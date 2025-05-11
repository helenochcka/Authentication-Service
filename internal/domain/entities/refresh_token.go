package entities

import "time"

type RefreshToken struct {
	TokenSha    string
	UserId      string
	TokenBcrypt string
	ExpiresAt   time.Time
	Used        bool
	UserAgent   string
	IpAddress   string
	AccessJTI   string
}
