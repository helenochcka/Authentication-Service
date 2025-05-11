package main

import (
	"Authentication-Service/config"
	"Authentication-Service/internal/auth_service/services"
	"Authentication-Service/internal/auth_service/use_cases"
	"Authentication-Service/internal/clients"
	"Authentication-Service/internal/handlers"
	"Authentication-Service/internal/middlewares"
	"Authentication-Service/internal/repositories/postgres"
	"Authentication-Service/internal/repositories/redis"
	"Authentication-Service/pkg/db"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"log"
	"strconv"

	_ "Authentication-Service/docs"
)

// @title Authentication-Service API
// @version 1.0
// @description REST API for authentication
// @securitydefinitions.apikey ApiKeyAuth
// @in	header
// @name	Authorization
// @query.collection.format multi
// @host      localhost:8080
// @schemes http
func main() {
	cfg := config.LoadYamlConfig("config/config.yaml")

	dataBase, err := db.ConnectDatabase(cfg.DB.Host, cfg.DB.Port, cfg.DB.UserName, cfg.DB.Password, cfg.DB.DBName)
	if err != nil {
		log.Fatal(err)
	}
	r := gin.Default()

	redisClient := clients.ProduceRedisClient(cfg.Redis.Uri)
	httpClient := clients.ProduceHTTPClient(cfg.Webhook.Url, cfg.Webhook.TimeOut)

	tr := postgres.NewTokenRepoPsSQL(dataBase)
	jr := redis.NewJTIRepoRedis(redisClient)

	as := services.NewAuthService(cfg.Server.SecretKey, cfg.Server.TokenExpTime, jr)
	ts := services.NewTokenService(tr, cfg.Server.TokenExpTime, cfg.Server.SecretKey)
	wn := services.NewWebhookNotifier(cfg.Webhook.Url, httpClient)

	luc := use_cases.NewLoginUseCase(as, ts)
	ruc := use_cases.NewRefreshUseCase(as, ts, wn)
	duc := use_cases.NewDeauthorizeUseCase(as, ts)

	ah := handlers.NewAuthHandler(luc, ruc, duc)

	auc := use_cases.NewAuthUseCase(as)
	am := middlewares.NewAuthMiddleware(auc)

	r.POST("/login", am.GetHeaders(), ah.Login)
	r.PUT("/tokens/refresh", am.GetHeaders(), ah.RefreshTokens)
	r.GET("/users/guid", am.AuthUser(), ah.GetUserId)
	r.POST("/logout", ah.Logout)

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	_ = r.Run(cfg.Server.Address + ":" + strconv.Itoa(cfg.Server.Port))
}
