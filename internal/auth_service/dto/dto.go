package dto

type AccessTokenPayload struct {
	UserId    string
	ExpiresAt int64
	JTI       string
}

type TokenPair struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"c29tZS1iYXNlNjQtcmVmcmVzaC10b2tlbg=="`
}

type UserData struct {
	UserAgent string
	IpAddress string
}

type UserId struct {
	UserId string `form:"user_id" example:"12345"`
}

type SuspiciousIpPayload struct {
	UserId    string `json:"user_id"`
	OldIp     string `json:"old_ip"`
	NewIp     string `json:"new_ip"`
	UserAgent string `json:"user_agent"`
}
