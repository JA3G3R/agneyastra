package services

type Status string

const ( 
	StatusVulnerable Status = "vulnerable:true"
	StatusSafe Status = "vulnerable:false"
	StatusError Status = "error"
	StatusUnknown Status = "vulnerable:unknown"
)


