package postgres

import (
	"Authentication-Service/internal/domain/entities"
	"Authentication-Service/internal/repositories"
	"database/sql"
)

type RefreshTokenRepoPG struct {
	db *sql.DB
}

func NewRefreshTokenRepoPG(db *sql.DB) *RefreshTokenRepoPG {
	return &RefreshTokenRepoPG{db: db}
}

func (rtr *RefreshTokenRepoPG) GetOne(tokenSHA string) (*entities.RefreshToken, error) {
	query := "SELECT token_sha, user_id, token_bcrypt, expires_at, used, user_agent, ip_address, access_jti FROM refresh_tokens WHERE token_sha = $1"
	rows, err := rtr.db.Query(query, tokenSHA)
	if err != nil {
		return nil, err
	}

	var refreshToken entities.RefreshToken
	if rows.Next() {
		if err = rows.Scan(
			&refreshToken.TokenSha,
			&refreshToken.UserId,
			&refreshToken.TokenBcrypt,
			&refreshToken.ExpiresAt,
			&refreshToken.Used,
			&refreshToken.UserAgent,
			&refreshToken.IpAddress,
			&refreshToken.AccessJTI,
		); err != nil {
			return nil, err
		}
	} else {
		return nil, repositories.ErrRecNotFound
	}

	if rows.Next() {
		return nil, repositories.ErrMultipleRecFound
	}

	return &refreshToken, nil
}

func (rtr *RefreshTokenRepoPG) Insert(refreshToken *entities.RefreshToken) error {
	stmt := "INSERT INTO refresh_tokens (token_sha, user_id, token_bcrypt, expires_at, used, user_agent, ip_address, access_jti) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
	err := rtr.db.QueryRow(stmt,
		refreshToken.TokenSha,
		refreshToken.UserId,
		refreshToken.TokenBcrypt,
		refreshToken.ExpiresAt,
		refreshToken.Used,
		refreshToken.UserAgent,
		refreshToken.IpAddress,
		refreshToken.AccessJTI).Err()
	if err != nil {
		return err
	}

	return nil
}

func (rtr *RefreshTokenRepoPG) Update(refreshToken *entities.RefreshToken) error {
	stmt := "UPDATE refresh_tokens SET user_id=$1, token_bcrypt=$2, expires_at=$3, used=$4, user_agent=$5, ip_address=$6, access_jti=$7 WHERE token_sha = $8"
	_, err := rtr.db.Exec(stmt,
		refreshToken.UserId,
		refreshToken.TokenBcrypt,
		refreshToken.ExpiresAt,
		refreshToken.Used,
		refreshToken.UserAgent,
		refreshToken.IpAddress,
		refreshToken.AccessJTI,
		refreshToken.TokenSha)
	if err != nil {
		return err
	}

	return nil
}
