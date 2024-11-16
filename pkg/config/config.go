package config

var instance *Config

func GetConfig() *Config {

    instance = &Config{}
    return instance

}

func GetAuthConfig() *AuthConfig {

    return &AuthConfig{}

}
