package rtdb

import (
	"github.com/JA3G3R/agneyastra/services"
)

type Result struct {

	ProjectId string
	RTDBUrl string
	Success services.Status
	Error error
	StatusCode string
	Body []byte
	AuthType string
}