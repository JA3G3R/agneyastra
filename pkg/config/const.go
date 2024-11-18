package config

import (
	"github.com/JA3G3R/agneyastra/utils"
)

var ApiKey string
var Debug bool
var ProjectConfig utils.ProjectConfig
var ProjectIds []string
var RTDBUrls map[string][]string

// to avoid cyclic dependency between packages