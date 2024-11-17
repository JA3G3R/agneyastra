package config

import (
	"log"

	"github.com/spf13/viper"
)

var instance *Config



func GetConfig() *Config {

    instance = &Config{}
    return instance

}

func GetAuthConfig() *AuthConfig {

    return &AuthConfig{}

}
