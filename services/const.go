package services

type Status string

const ( 
	StatusVulnerable Status = "vulnerable:true"
	StatusSafe Status = "vulnerable:false"
	StatusError Status = "error"
	StatusUnknown Status = "vulnerable:unknown"
)

type Remediations map[string]map[string]map[string]string
type VulnConfig map[string]map[string]map[string]string
var Remedies = Remediations{

	"auth": {
		"anon":        {
			"this": "Disable Anonymous Authentication",
		} ,
		"signup":       {
			"this": "Disable User Signup from Firebase Console",
		},

		"send-signin-link": {
			"this": "Disable Send Sign in Link from Firebase Console",
		},
		"custom-token-login": {
			"this": "Disable Custom Token Login from Firebase Console",
		},
	},

	"firestore": {
		"read": {
			"public":       "Disallow all read access using 'match /{document=**} { allow read: if false; }'.",
			"anon":         "Allow only authenticated access: 'allow read: if request.auth != null;'.",
			"signup":       "Allow access for verified users or specific roles: 'allow read: if request.auth.token.role == \"user\";'.",
			"custom-token": "Restrict to users with valid custom tokens: 'allow read: if request.auth.token.customClaim == true;'.",
		},
		"write": {
			"public":       "Disallow all write access using 'match /{document=**} { allow write: if false; }'.",
			"anon":         "Allow writes only for authenticated users: 'allow write: if request.auth != null;'.",
			"signup":       "Restrict writes to specific roles: 'allow write: if request.auth.token.role == \"editor\";'.",
			"custom-token": "Restrict writes to users with valid custom tokens: 'allow write: if request.auth.token.customClaim == true;'.",
		},
		"delete": {
			"public":       "Disallow all delete operations: 'match /{document=**} { allow delete: if false; }'.",
			"anon":         "Restrict to authenticated users: 'allow delete: if request.auth != null;'.",
			"signup":       "Allow for specific roles or users: 'allow delete: if request.auth.token.role == \"admin\";'.",
			"custom-token": "Restrict delete operations to users with valid custom tokens: 'allow delete: if request.auth.token.customClaim == true;'.",
		},
	},
	"rtdb": {
		"read": {
			"public":       "Set rules to disallow: '.read': 'auth != null'.",
			"anon":         "Allow authenticated users only: '.read': 'auth != null'.",
			"signup":       "Allow verified users based on roles: '.read': 'auth.token.role == \"user\"'.",
			"custom-token": "Restrict to users with valid claims: '.read': 'auth.token.customClaim == true'.",
		},
		"write": {
			"public":       "Set rules to disallow: '.write': 'false'.",
			"anon":         "Restrict writes to authenticated users: '.write': 'auth != null'.",
			"signup":       "Restrict to specific roles or users: '.write': 'auth.token.role == \"editor\"'.",
			"custom-token": "Restrict writes to users with valid claims: '.write': 'auth.token.customClaim == true'.",
		},
		"delete": {
			"public":       "Set rules to disallow delete: '.write': 'false'.",
			"anon":         "Restrict deletes to authenticated users: '.write': 'auth != null'.",
			"signup":       "Allow for specific roles or users: '.write': 'auth.token.role == \"admin\"'.",
			"custom-token": "Restrict deletes to users with valid claims: '.write': 'auth.token.customClaim == true'.",
		},
	},
	"bucket": {
		"read": {
			"public":       "Disable public read access: 'allow read: if false;'.",
			"anon":         "Restrict to authenticated users: 'allow read: if request.auth != null;'.",
			"signup":       "Restrict to specific roles or verified users: 'allow read: if request.auth.token.role == \"user\";'.",
			"custom-token": "Restrict to users with valid claims: 'allow read: if request.auth.token.customClaim == true;'.",
		},
		"write": {
			"public":       "Disable public write access: 'allow write: if false;'.",
			"anon":         "Restrict to authenticated users: 'allow write: if request.auth != null;'.",
			"signup":       "Restrict writes to verified roles: 'allow write: if request.auth.token.role == \"editor\";'.",
			"custom-token": "Restrict writes to users with valid claims: 'allow write: if request.auth.token.customClaim == true;'.",
		},
		"delete": {
			"public":       "Disable public delete access: 'allow delete: if false;'.",
			"anon":         "Restrict deletes to authenticated users: 'allow delete: if request.auth != null;'.",
			"signup":       "Allow for specific roles or users: 'allow delete: if request.auth.token.role == \"admin\";'.",
			"custom-token": "Restrict deletes to users with valid claims: 'allow delete: if request.auth.token.customClaim == true;'.",
		},
	},
}


var VulnConfigs = VulnConfig{
	"auth" : {
		"anon":      {"this": "Anonymous Authentication enabled in Firebase project.",},   
		"signup":   {"this": "User Signup Enabled in Firebase project.", },   
		"send-signin-link": {"this": "Send Sign in Link enabled in Firebase project.", },
		"custom-token-login": {"this": "Custom Token login enabled in Firebase project.",},
	},
	"firestore": {
		"read": {
			"public":       "match /{document=**} { allow read: if true; } // Allows unrestricted public access.",
			"anon":         "match /{document=**} { allow read: if request.auth == null; } // Allows unauthenticated access.",
			"signup":       "match /{document=**} { allow read: if request.auth != null; } // Permits all authenticated users without role validation.",
			"custom-token": "match /{document=**} { allow read: if true; } // Grants access without verifying custom tokens.",
		},
		"write": {
			"public":       "match /{document=**} { allow write: if true; } // Allows public write access.",
			"anon":         "match /{document=**} { allow write: if request.auth == null; } // Allows unauthenticated users to write.",
			"signup":       "match /{document=**} { allow write: if request.auth != null; } // Permits all authenticated users without role validation.",
			"custom-token": "match /{document=**} { allow write: if true; } // Grants write access without verifying custom tokens.",
		},
		"delete": {
			"public":       "match /{document=**} { allow delete: if true; } // Allows public delete access.",
			"anon":         "match /{document=**} { allow delete: if request.auth == null; } // Permits unauthenticated users to delete.",
			"signup":       "match /{document=**} { allow delete: if request.auth != null; } // Permits all authenticated users without role validation.",
			"custom-token": "match /{document=**} { allow delete: if true; } // Grants delete access without verifying custom tokens.",
		},
	},
	"rtdb": {
		"read": {
			"public":       ".read: true // Allows anyone to read data.",
			"anon":         ".read: !auth // Allows unauthenticated users to read.",
			"signup":       ".read: auth != null // Permits all authenticated users without role validation.",
			"custom-token": ".read: true // Grants read access without verifying custom claims.",
		},
		"write": {
			"public":       ".write: true // Allows anyone to write data.",
			"anon":         ".write: !auth // Allows unauthenticated users to write.",
			"signup":       ".write: auth != null // Permits all authenticated users without role validation.",
			"custom-token": ".write: true // Grants write access without verifying custom claims.",
		},
		"delete": {
			"public":       ".write: true // Allows anyone to delete data.",
			"anon":         ".write: !auth // Allows unauthenticated users to delete.",
			"signup":       ".write: auth != null // Permits all authenticated users without role validation.",
			"custom-token": ".write: true // Grants delete access without verifying custom claims.",
		},
	},
	"bucket": {
		"read": {
			"public":       "allow read: if true; // Allows unrestricted public access to storage objects.",
			"anon":         "allow read: if request.auth == null; // Allows unauthenticated access to storage objects.",
			"signup":       "allow read: if request.auth != null; // Permits access to all authenticated users without role validation.",
			"custom-token": "allow read: if true; // Grants access without validating custom tokens.",
		},
		"write": {
			"public":       "allow write: if true; // Allows public write access to storage objects.",
			"anon":         "allow write: if request.auth == null; // Allows unauthenticated access to write storage objects.",
			"signup":       "allow write: if request.auth != null; // Permits all authenticated users without role validation.",
			"custom-token": "allow write: if true; // Grants write access without validating custom tokens.",
		},
		"delete": {
			"public":       "allow delete: if true; // Allows public delete access to storage objects.",
			"anon":         "allow delete: if request.auth == null; // Permits unauthenticated users to delete storage objects.",
			"signup":       "allow delete: if request.auth != null; // Permits all authenticated users without role validation.",
			"custom-token": "allow delete: if true; // Grants delete access without validating custom tokens.",
		},
	},
}

