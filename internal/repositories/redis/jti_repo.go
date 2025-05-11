package redis

import (
	"Authentication-Service/internal/auth_service/services"
	"context"
	"github.com/redis/go-redis/v9"
	"time"
)

type JTIRepoRedis struct {
	c *redis.Client
}

func NewJTIRepoRedis(c *redis.Client) services.JTIRepo {
	return &JTIRepoRedis{c: c}
}

func (jr JTIRepoRedis) GetOne(jti string) (bool, error) {
	exists, err := jr.c.Exists(context.Background(), jti).Result()
	if err != nil {
		return false, err
	}
	return exists == 1, nil
}

func (jr JTIRepoRedis) Insert(jti string, expiresAt int64) error {
	ttl := time.Second * time.Duration(expiresAt-time.Now().Unix())
	err := jr.c.Set(context.Background(), jti, "", ttl).Err()
	if err != nil {
		return err
	}
	return nil
}
