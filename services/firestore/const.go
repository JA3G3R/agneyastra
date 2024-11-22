package firestore

import "github.com/JA3G3R/agneyastra/services"

type FirestoreDocumentAdded struct {
	DocumentID string `json:"documentID"`
	DocumentContent interface{} `json:"documentContent"`
	ProjectID string `json:"projectId"`
}

type Result struct {
	ProjectId string
	Success services.Status
	Error error
	StatusCode string
	AuthType string
}