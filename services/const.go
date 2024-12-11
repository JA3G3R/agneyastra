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
			"remedy": "Disable Anonymous Authentication",
		} ,
		"signup":       {
			"remedy": "Disable User Signup from Firebase Console",
		},

		"send-signin-link": {
			"remedy": "Disable Send Sign in Link from Firebase Console",
		},
		"custom-token-login": {
			"remedy": "Disable Custom Token Login from Firebase Console",
		},
	},

	"firestore": {
		"read": {
			"public":       "Allow access only if authenticated: 'allow read: if request.auth != null;' or 'allow read: if request.auth.token.role == \"<user-role>\";'.",
			"anon":         "Allow only authenticated access: 'allow read: if request.auth != null;' or 'allow read: if request.auth.token.role == \"<user-role>\";' or 'match /users/{userId} { allow read: if request.auth != null && request.auth.uid == userId;}' .",
			"signup":       "Allow access for verified users or specific roles: 'allow read: if request.auth.token.role == \"<user-role>\";' or 'match /users/{userId} { allow read: if request.auth != null && request.auth.uid == userId;}'.",
			"custom-token": "Restrict to users with valid custom tokens: 'allow read: if request.auth.token.customClaim == true;'.",
		},
		"write": {
			"public":       "Allow access only if authenticated: 'allow write: if request.auth != null;' or 'allow write: if request.auth.token.role == \"<user-role>\";'.",
			"anon":         "Allow writes only for authenticated users: 'allow write: if request.auth != null;' or 'allow write: if request.auth.token.role == \"<user-role>\";' or 'match /users/{userId} { allow write: if request.auth != null && request.auth.uid == userId;}'.",
			"signup":       "Restrict writes to specific roles: 'allow write: if request.auth.token.role == \"<user-role>\";' or 'match /users/{userId} { allow write: if request.auth != null && request.auth.uid == userId;}'.",
			"custom-token": "Restrict writes to users with valid custom tokens: 'allow write: if request.auth.token.customClaim == true;'.",
		},
		"delete": {
			"public":       "Allow access only if authenticated: 'allow delete: if request.auth != null;' or 'allow delete: if request.auth.token.role == \"<user-role>\";' .",
			"anon":         "Restrict to authenticated users: 'allow delete: if request.auth != null;' or 'allow delete: if request.auth.token.role == \"<user-role>\";' or 'match /users/{userId} { allow delete: if request.auth != null && request.auth.uid == userId;}'.",
			"signup":       "Allow for specific roles or users: 'allow delete: if request.auth.token.role == \"<user-role>\";' or 'match /users/{userId} { allow delete: if request.auth != null && request.auth.uid == userId;}'.",
			"custom-token": "Restrict delete operations to users with valid custom tokens: 'allow delete: if request.auth.token.customClaim == true;'.",
		},
	},
	"rtdb": {
		"read": {
			"public":       "Allow access only if authenticated: '.read': 'auth != null' or '.read': 'auth.token.role == \"<user-role>\"'.",
			"anon":         "Allow authenticated users only: '.read': 'auth != null' or '.read': 'auth.token.role == \"<user-role>\"' or '\"$uid\": {\".read\": \"$uid === auth.uid\"}'.",
			"signup":       "Allow verified users based on roles: '.read': 'auth.token.role == \"<user-role>\"' or '\"$uid\": {\".read\": \"$uid === auth.uid\"}'.",
			"custom-token": "Restrict to users with valid claims: '.read': 'auth.token.customClaim == true'.",
		},
		"write": {
			"public":       "Allow writes only if authenticated: '.write': 'auth != null' or '.write': 'auth.token.role == \"<user-role>\"'.",
			"anon":         "Restrict writes to authenticated users: '.write': 'auth != null' or '.write': 'auth.token.role == \"editor\"' or '\"$uid\": {\".write\": \"$uid === auth.uid\"}'.",
			"signup":       "Restrict to specific roles or users: '.write': 'auth.token.role == \"editor\"' or '\"$uid\": {\".write\": \"$uid === auth.uid\"}'.",
			"custom-token": "Restrict writes to users with valid claims: '.write': 'auth.token.customClaim == true'.",
		},
		"delete": {
			"public":       "Allow delete operations only if authenticated: '.delete': 'auth != null' or '.delete': 'auth.token.role == \"<user-role>\"'.",
			"anon":         "Restrict deletes to authenticated users: '.delete': 'auth != null' or '.delete': 'auth.token.role == \"admin\"' or '\"$uid\": {\".delete\": \"$uid === auth.uid\"}'.",
			"signup":       "Allow for specific roles or users: '.delete': 'auth.token.role == \"admin\"' or '\"$uid\": {\".delete\": \"$uid === auth.uid\"}'.",
			"custom-token": "Restrict deletes to users with valid claims: '.delete': 'auth.token.customClaim == true'.",
		},
	},
	"bucket": {
		"read": {
			"public":       "Disable public read access: 'allow read: if request.auth != null;' or allow read: if request.auth.token.role == \"<user-id>\";'.",
			"anon":         "Restrict to authenticated users: 'allow read: if request.auth != null;' or 'allow read: if request.auth.token.role == \"<user-id>\";' or 'match /user_files/{userId}/{allPaths=**} { allow read: if request.auth != null && request.auth.uid == userId; }'.",
			"signup":       "Restrict to specific roles or verified users: 'allow read: if request.auth.token.role == \"<user-id>\";' or 'match /user_files/{userId}/{allPaths=**} { allow read: if request.auth != null && request.auth.uid == userId; }'.",
			"custom-token": "Restrict to users with valid claims: 'allow read: if request.auth.token.customClaim == true;'.",
		},
		"write": {
			"public":       "Disable public write access: 'allow write: if request.auth != null;' or allow write: if request.auth.token.role == \"<user-id>\";'.",
			"anon":         "Restrict to authenticated users: 'allow write: if request.auth != null;' or 'allow write: if request.auth.token.role == \"editor\";' or 'match /user_files/{userId}/{allPaths=**} { allow write: if request.auth != null && request.auth.uid == userId; }'.",
			"signup":       "Restrict writes to verified roles: 'allow write: if request.auth.token.role == \"editor\";' or 'match /user_files/{userId}/{allPaths=**} { allow write: if request.auth != null && request.auth.uid == userId; }'.",
			"custom-token": "Restrict writes to users with valid claims: 'allow write: if request.auth.token.customClaim == true;'.",
		},
		"delete": {
			"public":       "Disable public write access: 'allow delete: if request.auth != null;' or allow delete: if request.auth.token.role == \"<user-id>\";'.",
			"anon":         "Restrict deletes to authenticated users: 'allow delete: if request.auth != null;' or 'allow delete: if request.auth.token.role == \"admin\";' or 'match /user_files/{userId}/{allPaths=**} { allow delete: if request.auth != null && request.auth.uid == userId; }'.",
			"signup":       "Allow for specific roles or users: 'allow delete: if request.auth.token.role == \"admin\";' or 'match /user_files/{userId}/{allPaths=**} { allow delete: if request.auth != null && request.auth.uid == userId; }'.",
			"custom-token": "Restrict deletes to users with valid claims: 'allow delete: if request.auth.token.customClaim == true;'.",
		},
	},
}


var VulnConfigs = VulnConfig{
	"auth" : {
		"anon":      {"config": "Anonymous Authentication enabled in Firebase project.",},   
		"signup":   {"config": "User Signup Enabled in Firebase project.", },   
		"send-signin-link": {"config": "Send Sign in Link enabled in Firebase project.", },
		"custom-token-login": {"config": "Custom Token login enabled in Firebase project.",},
	},
	"firestore": {
		"read": {
			"public":       "match /{document=**} { allow read: if true; } // Allows unrestricted public access.",
			"anon":         "match /{document=**} { allow read: if request.auth == null; } // Allows unauthenticated access.",
			"signup":       "match /{document=**} { allow read: if request.auth != null; } // Permits all authenticated users without role/userid validation.",
			"custom-token": "match /{document=**} { allow read: if true; } // Grants access without verifying custom tokens.",
		},
		"write": {
			"public":       "match /{document=**} { allow write: if true; } // Allows public write access.",
			"anon":         "match /{document=**} { allow write: if request.auth == null; } // Allows unauthenticated users to write.",
			"signup":       "match /{document=**} { allow write: if request.auth != null; } // Permits all authenticated users without role/userid validation.",
			"custom-token": "match /{document=**} { allow write: if true; } // Grants write access without verifying custom tokens.",
		},
		"delete": {
			"public":       "match /{document=**} { allow delete: if true; } // Allows public delete access.",
			"anon":         "match /{document=**} { allow delete: if request.auth == null; } // Permits unauthenticated users to delete.",
			"signup":       "match /{document=**} { allow delete: if request.auth != null; } // Permits all authenticated users without role/userid validation.",
			"custom-token": "match /{document=**} { allow delete: if true; } // Grants delete access without verifying custom tokens.",
		},
	},
	"rtdb": {
		"read": {
			"public":       ".read: true // Allows anyone to read data.",
			"anon":         ".read: !auth // Allows unauthenticated users to read.",
			"signup":       ".read: auth != null // Permits all authenticated users without role/userid validation.",
			"custom-token": ".read: true // Grants read access without verifying custom claims.",
		},
		"write": {
			"public":       ".write: true // Allows anyone to write data.",
			"anon":         ".write: !auth // Allows unauthenticated users to write.",
			"signup":       ".write: auth != null // Permits all authenticated users without role/userid validation.",
			"custom-token": ".write: true // Grants write access without verifying custom claims.",
		},
		"delete": {
			"public":       ".write: true // Allows anyone to delete data.",
			"anon":         ".write: !auth // Allows unauthenticated users to delete.",
			"signup":       ".write: auth != null // Permits all authenticated users without role/userid validation.",
			"custom-token": ".write: true // Grants delete access without verifying custom claims.",
		},
	},
	
	"bucket": {
		"read": {
			"public":       "allow read: if true; // Allows unrestricted public access to storage objects.",
			"anon":         "allow read: if request.auth == null; // Allows unauthenticated access to storage objects.",
			"signup":       "allow read: if request.auth != null; // Permits access to all authenticated users without role/userid validation.",
			"custom-token": "allow read: if true; // Grants access without validating custom tokens.",
		},
		"write": {
			"public":       "allow write: if true; // Allows public write access to storage objects.",
			"anon":         "allow write: if request.auth == null; // Allows unauthenticated access to write storage objects.",
			"signup":       "allow write: if request.auth != null; // Permits all authenticated users without role/userid validation.",
			"custom-token": "allow write: if true; // Grants write access without validating custom tokens.",
		},
		"delete": {
			"public":       "allow delete: if true; // Allows public delete access to storage objects.",
			"anon":         "allow delete: if request.auth == null; // Permits unauthenticated users to delete storage objects.",
			"signup":       "allow delete: if request.auth != null; // Permits all authenticated users without role/userid validation.",
			"custom-token": "allow delete: if true; // Grants delete access without validating custom tokens.",
		},
	},
}

