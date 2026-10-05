package google

import (
	"testing"

	"github.com/JA3G3R/agneyastra/internal/httpx"
)

func r(status int, body string) *httpx.Response {
	return &httpx.Response{Status: status, Body: []byte(body)}
}

func TestMapsJSON(t *testing.T) {
	if !mapsJSON(r(200, `{"status":"OK","results":[]}`)) {
		t.Error("clean OK should be enabled")
	}
	if !mapsJSON(r(200, `{"status":"ZERO_RESULTS"}`)) {
		t.Error("ZERO_RESULTS still means the API is enabled")
	}
	if mapsJSON(r(200, `{"error_message":"This API project is not authorized...","status":"REQUEST_DENIED"}`)) {
		t.Error("REQUEST_DENIED with error_message must NOT be enabled (blast-radius FP guard)")
	}
	if mapsJSON(r(200, `{"status":"REQUEST_DENIED","errorMessage":"denied"}`)) {
		t.Error("timezone-style errorMessage must NOT be enabled")
	}
	if mapsJSON(r(403, `denied`)) {
		t.Error("403 must not be enabled")
	}
}

func TestNoErrorField(t *testing.T) {
	if !noErrorField(r(200, `{"snappedPoints":[]}`)) {
		t.Error("roads success should be enabled")
	}
	if noErrorField(r(200, `{"error":{"code":403,"message":"denied"}}`)) {
		t.Error("body with error object should not be enabled")
	}
}

func TestNotDenied(t *testing.T) {
	if notDenied(r(403, `forbidden`)) {
		t.Error("403 should be denied")
	}
	if notDenied(r(400, `{"error":{"message":"API key not valid"}}`)) {
		t.Error("API_KEY invalid should be denied")
	}
	if !notDenied(r(400, `{"error":{"message":"Invalid Value for cx"}}`)) {
		t.Error("400 bad-param (not an auth error) should count as enabled")
	}
	if !notDenied(r(200, `{"items":[]}`)) {
		t.Error("200 should be enabled")
	}
}
