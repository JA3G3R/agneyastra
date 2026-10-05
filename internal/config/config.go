// Package config holds the embedded default configuration. The previous version
// downloaded config.yaml and the HTML template from GitHub on every startup;
// everything ships in the binary now, so agneyastra runs fully offline except
// for the checks themselves.
package config

import _ "embed"

//go:embed default_config.yaml
var DefaultConfigYAML []byte
