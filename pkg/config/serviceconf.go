package config

import "github.com/spf13/viper"

func GetAuthConfig()  {

    globalConfig := GetConfig()
        
    apiKey := viper.GetString("services.auth.api_key")
    endpoint := viper.GetString("services.auth.endpoint")
    
}

func GetStorageConfig() (string, string) {

    bucketName := viper.GetString("services.storage.bucket_name")
    region := viper.GetString("services.storage.region")
    return bucketName, region
    
}
