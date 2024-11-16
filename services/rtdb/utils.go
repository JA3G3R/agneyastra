package rtdb

import "fmt"

func CreateRTDBURLs(domains []string) []string {
    var urls []string
    // Generate URLs with .firebaseio.com and -default-rtdb.firebaseio.com
    for _, domain := range domains {
        urls = append(urls, fmt.Sprintf("https://%s.firebaseio.com", domain))
        urls = append(urls, fmt.Sprintf("https://%s-default-rtdb.firebaseio.com", domain))
    }
	return urls
}