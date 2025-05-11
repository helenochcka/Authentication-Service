package entities

type AccessToken struct {
	UserId    string
	ExpiresAt int64
	JTI       string
}
