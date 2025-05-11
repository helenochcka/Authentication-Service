package pgdb

import (
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/lib/pq"
)

func ConnectDatabase(host string, port int, user string, password string, dbname string) (*sql.DB, error) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	dataBase, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, errors.New("error connecting to database")
	}

	return dataBase, nil
}
