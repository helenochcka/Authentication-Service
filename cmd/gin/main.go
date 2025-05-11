package main

import (
	"Authentication-Service/config"
	"Authentication-Service/internal/domain/services"
	"Authentication-Service/internal/domain/use_cases"
	"Authentication-Service/internal/handlers"
	"Authentication-Service/internal/middlewares"
	"Authentication-Service/internal/repositories/postgres"
	"Authentication-Service/internal/repositories/redis"
	"Authentication-Service/pkg/clients"
	"Authentication-Service/pkg/pgdb"
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

	db, err := pgdb.ConnectDatabase(cfg.DB.Host, cfg.DB.Port, cfg.DB.UserName, cfg.DB.Password, cfg.DB.DBName)
	if err != nil {
		log.Fatal(err)
	}
	r := gin.Default()

	rc := clients.ProduceRedisClient(cfg.Redis.Host, cfg.Redis.Port)
	wc := clients.NewWebhookHTTPClient(cfg.Webhook.Host, cfg.Webhook.TimeOut)

	tr := postgres.NewRefreshTokenRepoPG(db)
	jr := redis.NewJTIRepoRedis(rc)

	as := services.NewAccessTokenService(cfg.Server.SecretKey, cfg.Server.TokenExpTime, jr)
	ts := services.NewRefreshTokenService(tr, cfg.Server.TokenExpTime)
	wn := services.NewWebhookService(wc)

	linuc := use_cases.NewLoginUseCase(as, ts)
	ruc := use_cases.NewRefreshUseCase(as, ts, wn)
	loutuc := use_cases.NewLogoutUseCase(as, ts)

	ah := handlers.NewAuthHandler(linuc, ruc, loutuc)

	auc := use_cases.NewAuthUseCase(as)
	am := middlewares.NewAuthMiddleware(auc)

	r.POST("/login", ah.Login)
	r.PUT("/tokens/refresh", ah.RefreshTokens)
	r.GET("/users/guid", am.AuthUser(), ah.GetUserId)
	r.POST("/logout", ah.Logout)

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	_ = r.Run(cfg.Server.Host + ":" + strconv.Itoa(cfg.Server.Port))
}
