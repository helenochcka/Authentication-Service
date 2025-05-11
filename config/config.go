package config

import (
	"gopkg.in/yaml.v3"
	"log"
	"os"
)

type Config struct {
	Server struct {
		Host         string `yaml:"host"`
		Port         int    `yaml:"port"`
		SecretKey    string `yaml:"secret_key"`
		TokenExpTime int    `yaml:"token_exp_time"`
	} `yaml:"server"`

	DB struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		UserName string `yaml:"user_name"`
		Password string `yaml:"password"`
		DBName   string `yaml:"dbname"`
	} `yaml:"db"`

	Webhook struct {
		Host    string `yaml:"host"`
		TimeOut int    `yaml:"time_out"`
	} `yaml:"webhook"`

	Redis struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"redis"`
}

func LoadYamlConfig(filepath string) Config {
	data, err := os.ReadFile(filepath)

	if err != nil {
		log.Fatalf("Error reading configuration file: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)

	if err != nil {
		log.Fatalf("Error unmarshalling YAML: %v", err)
	}

	return config
}
