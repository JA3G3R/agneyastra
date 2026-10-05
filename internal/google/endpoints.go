package google

import "github.com/JA3G3R/agneyastra/internal/httpx"

// endpoint describes one Google API that accepts a bare API key. The catalog
// below is what makes agneyastra a *generic* Google API-key blast-radius scanner
// rather than a Firebase-only tool: Google reuses the same AIza… key format
// across all of these, so a single leaked key may bill the owner or expose data
// through any service the key was not restricted away from.
type endpoint struct {
	name        string
	category    string // maps | messaging | genai | translation | youtube | safebrowsing | search
	method      string
	url         string // {KEY} is substituted at run time
	body        string // request body for POST endpoints
	contentType string
	headers     map[string]string
	severity    string // report.Severity value
	remediation string
	// enabled decides, from the response, whether the key is unrestricted for
	// this API (i.e. an attacker could abuse it).
	enabled func(*httpx.Response) bool
}

const restrict = "Restrict this API key in Google Cloud Console > APIs & Services > Credentials: add application restrictions (HTTP referrer / IP / Android / iOS) and API restrictions so the key only works for the specific APIs it needs."

// --- response classifiers -------------------------------------------------

// mapsJSON: the Maps web-service JSON APIs return HTTP 200 even when the key is
// unauthorized, signalling denial via an error_message/errorMessage field and a
// REQUEST_DENIED status. Absence of those means the key worked.
func mapsJSON(r *httpx.Response) bool {
	return r.Status == 200 &&
		!r.BodyContains("error_message") &&
		!r.BodyContains("errormessage") &&
		!r.BodyContains("request_denied")
}

// image200: the raster endpoints (Static Maps, Street View) return the image on
// success and a 403 when the key is rejected.
func image200(r *httpx.Response) bool { return r.Status == 200 }

// noErrorField: Roads/Geolocation return a top-level "error" object on denial.
func noErrorField(r *httpx.Response) bool {
	return r.Status == 200 && !r.BodyContains("\"error\"")
}

func status200(r *httpx.Response) bool { return r.Status == 200 }

func contains(needle string) func(*httpx.Response) bool {
	return func(r *httpx.Response) bool { return r.Status == 200 && r.BodyContains(needle) }
}

// notDenied: for APIs that answer 400 on a bad parameter while still being
// enabled — anything that is not an explicit auth denial counts as enabled.
func notDenied(r *httpx.Response) bool {
	if r.Status == 401 || r.Status == 403 || r.Status >= 500 {
		return false
	}
	if r.BodyContains("api_key_invalid") || r.BodyContains("permission_denied") ||
		r.BodyContains("request_denied") || r.BodyContains("service_disabled") ||
		r.BodyContains("has not been used in project") || r.BodyContains("api key not valid") {
		return false
	}
	return r.Status < 500
}

// catalog is the full set of probes.
var catalog = []endpoint{
	// --- Google Maps Platform ---
	{name: "Static Maps", category: "maps", method: "GET", severity: "medium", enabled: image200, remediation: restrict,
		url: "https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=7&size=400x400&key={KEY}"},
	{name: "Street View", category: "maps", method: "GET", severity: "medium", enabled: image200, remediation: restrict,
		url: "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key={KEY}"},
	{name: "Directions", category: "maps", method: "GET", severity: "medium", enabled: mapsJSON, remediation: restrict,
		url: "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood&key={KEY}"},
	{name: "Geocoding", category: "maps", method: "GET", severity: "medium", enabled: mapsJSON, remediation: restrict,
		url: "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={KEY}"},
	{name: "Distance Matrix", category: "maps", method: "GET", severity: "medium", enabled: mapsJSON, remediation: restrict,
		url: "https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615,-73.9976592&key={KEY}"},
	{name: "Places Find", category: "maps", method: "GET", severity: "medium", enabled: mapsJSON, remediation: restrict,
		url: "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum&inputtype=textquery&fields=formatted_address,name&key={KEY}"},
	{name: "Places Autocomplete", category: "maps", method: "GET", severity: "medium", enabled: mapsJSON, remediation: restrict,
		url: "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key={KEY}"},
	{name: "Place Details", category: "maps", method: "GET", severity: "medium", enabled: mapsJSON, remediation: restrict,
		url: "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating&key={KEY}"},
	{name: "Places Nearby", category: "maps", method: "GET", severity: "medium", enabled: mapsJSON, remediation: restrict,
		url: "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key={KEY}"},
	{name: "Places Text Search", category: "maps", method: "GET", severity: "medium", enabled: mapsJSON, remediation: restrict,
		url: "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key={KEY}"},
	{name: "Elevation", category: "maps", method: "GET", severity: "medium", enabled: mapsJSON, remediation: restrict,
		url: "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={KEY}"},
	{name: "Time Zone", category: "maps", method: "GET", severity: "medium", enabled: mapsJSON, remediation: restrict,
		url: "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={KEY}"},
	{name: "Nearest Roads", category: "maps", method: "GET", severity: "medium", enabled: noErrorField, remediation: restrict,
		url: "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795%7C60.170879,24.942796&key={KEY}"},
	{name: "Snap to Roads", category: "maps", method: "GET", severity: "medium", enabled: noErrorField, remediation: restrict,
		url: "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958%7C-35.28032,149.12907&interpolate=true&key={KEY}"},
	{name: "Speed Limits", category: "maps", method: "GET", severity: "medium", enabled: noErrorField, remediation: restrict,
		url: "https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key={KEY}"},
	{name: "Geolocation", category: "maps", method: "POST", severity: "medium", enabled: noErrorField, remediation: restrict,
		url: "https://www.googleapis.com/geolocation/v1/geolocate?key={KEY}", contentType: "application/json", body: `{"considerIp":true}`},
	{name: "Routes computeRoutes", category: "maps", method: "POST", severity: "medium", enabled: contains("routes"), remediation: restrict,
		url:         "https://routes.googleapis.com/directions/v2:computeRoutes?key={KEY}",
		contentType: "application/json",
		headers:     map[string]string{"X-Goog-FieldMask": "routes.duration,routes.distanceMeters"},
		body:        `{"origin":{"location":{"latLng":{"latitude":37.419734,"longitude":-122.0827784}}},"destination":{"location":{"latLng":{"latitude":37.417670,"longitude":-122.079595}}},"travelMode":"DRIVE"}`},
	{name: "Routes computeRouteMatrix", category: "maps", method: "POST", severity: "medium", enabled: notDenied, remediation: restrict,
		url:         "https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix?key={KEY}",
		contentType: "application/json",
		headers:     map[string]string{"X-Goog-FieldMask": "originIndex,destinationIndex,duration"},
		body:        `{"origins":[{"waypoint":{"location":{"latLng":{"latitude":37.42,"longitude":-122.08}}}}],"destinations":[{"waypoint":{"location":{"latLng":{"latitude":37.41,"longitude":-122.07}}}}],"travelMode":"DRIVE"}`},
	{name: "Address Validation", category: "maps", method: "POST", severity: "medium", enabled: status200, remediation: restrict,
		url:         "https://addressvalidation.googleapis.com/v1:validateAddress?key={KEY}",
		contentType: "application/json",
		body:        `{"address":{"regionCode":"US","addressLines":["1600 Amphitheatre Pkwy, Mountain View, CA"]}}`},
	{name: "Air Quality", category: "maps", method: "POST", severity: "medium", enabled: status200, remediation: restrict,
		url:         "https://airquality.googleapis.com/v1/currentConditions:lookup?key={KEY}",
		contentType: "application/json",
		body:        `{"location":{"latitude":37.419734,"longitude":-122.0827784}}`},

	// --- Generative AI (Gemini) ---
	{name: "Generative Language (Gemini)", category: "genai", method: "GET", severity: "high", enabled: contains("models"), remediation: restrict,
		url: "https://generativelanguage.googleapis.com/v1beta/models?key={KEY}"},

	// --- Cloud Translation ---
	{name: "Cloud Translation", category: "translation", method: "GET", severity: "medium", enabled: contains("languages"), remediation: restrict,
		url: "https://translation.googleapis.com/language/translate/v2/languages?key={KEY}"},

	// --- YouTube Data ---
	{name: "YouTube Data", category: "youtube", method: "GET", severity: "low", enabled: status200, remediation: restrict,
		url: "https://www.googleapis.com/youtube/v3/videos?part=id&chart=mostPopular&maxResults=1&key={KEY}"},

	// --- Safe Browsing ---
	{name: "Safe Browsing", category: "safebrowsing", method: "POST", severity: "low", enabled: status200, remediation: restrict,
		url:         "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={KEY}",
		contentType: "application/json",
		body:        `{"client":{"clientId":"agneyastra","clientVersion":"1.0"},"threatInfo":{"threatTypes":["MALWARE"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":"http://malware.testing.google.test/testing/malware/"}]}}`},

	// --- Custom Search ---
	{name: "Custom Search", category: "search", method: "GET", severity: "low", enabled: notDenied, remediation: restrict,
		url: "https://www.googleapis.com/customsearch/v1?key={KEY}&cx=017576662512468239146:omuauf_lfve&q=test"},
}
