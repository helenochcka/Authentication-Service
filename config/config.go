package config

type Config struct {
	Server struct {
		Address      string
		Port         int
		SecretKey    string `yaml:"secret_key"`
		TokenExpTime int    `yaml:"token_exp_time"`
	} `yaml:"server"`

	DB struct {
		Host     string
		Port     int
		UserName string `yaml:"user_name"`
		Password string
		DBName   string `yaml:"dbname"`
	} `yaml:"db"`

	Webhook struct {
		Url     string `yaml:"url"`
		TimeOut int    `yaml:"time_out"`
	} `yaml:"webhook"`

	Redis struct {
		Uri string `yaml:"uri"`
	}
}
