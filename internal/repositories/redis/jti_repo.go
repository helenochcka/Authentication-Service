package redis

import (
	"context"
	"github.com/redis/go-redis/v9"
	"time"
)

type JTIRepoRedis struct {
	c *redis.Client
}

func NewJTIRepoRedis(c *redis.Client) *JTIRepoRedis {
	return &JTIRepoRedis{c: c}
}

func (jtir JTIRepoRedis) Exists(jti string) (bool, error) {
	exists, err := jtir.c.Exists(context.Background(), jti).Result()
	if err != nil {
		return false, err
	}
	return exists == 1, nil
}

func (jtir JTIRepoRedis) Set(jti string, expiresAt int64) error {
	ttl := time.Second * time.Duration(expiresAt-time.Now().Unix())
	err := jtir.c.Set(context.Background(), jti, "", ttl).Err()
	if err != nil {
		return err
	}
	return nil
}
