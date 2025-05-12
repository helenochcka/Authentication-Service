package main

import (
	"Authentication-Service/config"
	"Authentication-Service/internal/domain/services"
	"Authentication-Service/internal/domain/use_cases"
	"Authentication-Service/internal/handlers"
	"Authentication-Service/internal/repositories/postgres"
	"Authentication-Service/internal/repositories/redis"
	"Authentication-Service/pkg/clients"
	"Authentication-Service/pkg/pgdb"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"log"
	"os"
	"strconv"

	_ "Authentication-Service/docs"
)

// @title	Authentication-Service API
// @version	1.0
// @securitydefinitions.apikey ApiKeyAuth
// @in		header
// @name	Authorization
// @query.collection.format multi
func main() {
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		panic("CONFIG_PATH environment variable not set")
	}

	cfg := config.LoadYamlConfig(cfgPath)

	db, err := pgdb.ConnectDatabase(cfg.DB.Host, cfg.DB.Port, cfg.DB.UserName, cfg.DB.Password, cfg.DB.DBName)
	if err != nil {
		log.Fatal(err)
	}
	r := gin.Default()

	rc := clients.ProduceRedisClient(cfg.Redis.Host, cfg.Redis.Port)
	wc := clients.NewWebhookHTTPClient(cfg.Webhook.Host, cfg.Webhook.TimeOutSec)

	tr := postgres.NewRefreshTokenRepoPG(db)
	jr := redis.NewJTIRepoRedis(rc)

	as := services.NewAccessTokenService(cfg.Server.SecretKey, cfg.Server.AccessTokenExpTime, jr)
	ts := services.NewRefreshTokenService(tr, cfg.Server.RefreshTokenExpTime)
	wn := services.NewWebhookService(wc)

	linuc := use_cases.NewLoginUseCase(as, ts)
	ruc := use_cases.NewRefreshUseCase(as, ts, wn)
	loutuc := use_cases.NewLogoutUseCase(as, ts)

	ah := handlers.NewAuthHandler(linuc, ruc, loutuc)

	auc := use_cases.NewAuthUseCase(as)
	am := handlers.NewAuthMiddleware(auc)

	r.POST("/login", ah.Login)
	r.PUT("/tokens/refresh", ah.RefreshTokens)
	r.GET("/users/guid", am.AuthUser(), ah.GetUserId)
	r.POST("/logout", ah.Logout)

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	_ = r.Run(cfg.Server.Host + ":" + strconv.Itoa(cfg.Server.Port))
}
