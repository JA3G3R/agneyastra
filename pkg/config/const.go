package config

import (
	"github.com/JA3G3R/agneyastra/utils"
)

var ApiKeyFile string
var ApiKeys []string = []string{}
var Debug bool
var ProjectConfig map[string]utils.ProjectConfig = map[string]utils.ProjectConfig{}
var ProjectIds map[string][]string = map[string][]string{}
var RTDBUrls map[string]map[string][]string = map[string]map[string][]string{}
var TemplateFile string
var ReportPath string
var Correlate bool
var SecretsExtract bool
var PentestDataFilePath string
var SecretsRegexFile string
var ProjectId string
var AssetExtract bool
// to avoid cyclic dependency between packages