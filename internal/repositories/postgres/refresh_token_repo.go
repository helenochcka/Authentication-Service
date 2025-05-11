package postgres

import (
	"Authentication-Service/internal/auth_service/entity"
	"Authentication-Service/internal/auth_service/services"
	"Authentication-Service/internal/repositories"
	"database/sql"
)

type TokenRepoPsSQL struct {
	DB *sql.DB
}

func NewTokenRepoPsSQL(db *sql.DB) services.TokenRepo {
	return &TokenRepoPsSQL{DB: db}
}

func (tr TokenRepoPsSQL) GetOne(tokenSHA string) (*entity.RefreshToken, error) {
	query := "SELECT token_sha, user_id, token_bcrypt, expires_at, used, user_agent, ip_address, access_jti FROM refresh_tokens WHERE token_sha = $1"
	rows, err := tr.DB.Query(query, tokenSHA)
	if err != nil {
		return nil, err
	}

	var refreshToken entity.RefreshToken
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

func (tr TokenRepoPsSQL) Insert(refreshToken *entity.RefreshToken) error {
	stmt := "INSERT INTO refresh_tokens (token_sha, user_id, token_bcrypt, expires_at, used, user_agent, ip_address, access_jti) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
	err := tr.DB.QueryRow(stmt,
		refreshToken.TokenSha,
		refreshToken.UserId,
		refreshToken.TokenBcrypt,
		refreshToken.ExpiresAt,
		refreshToken.Used,
		refreshToken.UserAgent,
		refreshToken.IpAddress,
		refreshToken.AccessJTI,
	).Err()
	if err != nil {
		return err
	}

	return nil
}

func (tr TokenRepoPsSQL) Update(refreshToken *entity.RefreshToken) error {
	stmt := "UPDATE refresh_tokens SET user_id=$1, token_bcrypt=$2, expires_at=$3, used=$4, user_agent=$5, ip_address=$6, access_jti=$7 WHERE token_sha = $8"
	_, err := tr.DB.Exec(stmt,
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
