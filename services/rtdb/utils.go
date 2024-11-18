package rtdb

import "fmt"

func CreateRTDBURLs(domains []string) map[string][]string {

    var urls map[string][]string = make(map[string][]string)
    // Generate URLs with .firebaseio.com and -default-rtdb.firebaseio.com
    for _, domain := range domains {
        urls[domain] = []string{}
        urls[domain] = append(urls[domain],fmt.Sprintf("https://%s.firebaseio.com", domain))
        urls[domain] = append(urls[domain], fmt.Sprintf("https://%s-default-rtdb.firebaseio.com", domain))
    }
	return urls
}