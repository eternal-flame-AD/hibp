package hibp

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	urllib "net/url"
)

var errNotFound = errors.New("not found")

// ErrRateLimited is returned when request limit is exceeded, wait for 2sec before sending another request
var ErrRateLimited = errors.New("rate limit exceeded")

func buildRequest(service string, param string, additionalParams map[string]string, isPwd bool) *http.Request {
	var eP string
	if isPwd {
		eP = endPointForPwd
	} else {
		eP = endPoint
	}
	var url string
	if param == "" {
		url = eP + service
	} else {
		url = eP + service + "/" + urllib.PathEscape(param)
	}
	if additionalParams != nil && len(additionalParams) > 0 {
		query := make(urllib.Values)
		for k, v := range additionalParams {
			query.Set(k, v)
		}
		url += "?" + query.Encode()
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", userAgent)
	return req
}

func makeRequest(req *http.Request) ([]byte, error) {
	client := http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case 200:
		resBytes, err := ioutil.ReadAll(res.Body)
		return resBytes, err
	case 404:
		return nil, errNotFound
	case 429:
		return nil, ErrRateLimited
	default:
		return nil, fmt.Errorf("remote returned %d", res.StatusCode)
	}
}
