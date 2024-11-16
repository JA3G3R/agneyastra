package firestore

type FirestoreDocumentAdded struct {
	DocumentID string `json:"documentID"`
	DocumentContent interface{} `json:"documentContent"`
	ProjectID string `json:"projectId"`
}