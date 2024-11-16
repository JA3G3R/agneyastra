package run

import (
	"github.com/JA3G3R/agneyastra/services/auth"
	"github.com/JA3G3R/agneyastra/services/storage"
	"github.com/JA3G3R/agneyastra/services/firestore"
	"github.com/JA3G3R/agneyastra/services/realtime"
	"github.com/JA3G3R/agneyastra/services/auth"
	flags "github.com/JA3G3R/agneyastra/flag"
	"github.com/JA3G3R/agneyastra/pkg/config"
)


func RunAll() {


	// flow
	// 1. Try email password auth -> Email password can be taken from a config file 
	// 2. try anon auth
	// 3. Try custom token auth
	// 4. Try new user sign up 
	// 5. Try send signin link

	// Service checks
	// storage bucket checks
	// firestore checks
	// realtime db checks
	//

	authConfig = config.GetAuthConfig()
	


	apiKey := flags.GetAPIKey()
	auth.AnonymousAuth(apiKey)

	
	

}