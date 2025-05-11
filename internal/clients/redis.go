package clients

import "github.com/redis/go-redis/v9"

func ProduceRedisClient(uri string) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     uri,
		Password: "",
		DB:       0,
	})
}
