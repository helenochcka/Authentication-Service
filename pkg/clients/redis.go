package clients

import (
	"github.com/redis/go-redis/v9"
	"strconv"
)

func ProduceRedisClient(host string, port int) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     host + ":" + strconv.Itoa(port),
		Password: "",
		DB:       0,
	})
}
