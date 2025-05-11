package config

import (
	"gopkg.in/yaml.v3"
	"log"
	"os"
)

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
