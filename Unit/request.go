package unit

import (
	"net/http"
	"net/url"
	"errors"
	"strings"
	"io"
	"time"
)

func CreateNewRequest(method string, requestURL string, body io.Reader, headers map[string]string,
	) (*http.Request, error) {
	req , err := http.NewRequest(method, requestURL, body)
	if err != nil {
		return nil, err
	}

	for key,value := range headers { 
		req.Header.Add(key,value)
	}

	return req, nil
}

func CreateClient() *http.Client {
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}

	return &http.Client{
		Transport: tr,
	}
}

func SendRequest(client *http.Client, method string, requestURL string, body io.Reader, headers map[string]string,
	) (*http.Response, int, time.Duration, error) {
	req, err := CreateNewRequest(method, requestURL, body, headers)
	if err != nil {
		return nil, 0,0, nil
	}

	start := time.Now()

	res, err := client.Do(req)
	elasped := time.Since(start)

	if err != nil {
		return nil, 0, elasped, err
	}

	return res, res.StatusCode, elasped, nil
}

func BuildUrl(url string, path string, https bool) (string) {
	if !https {
		if path == "" {
			return "http://" + url
		}

		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		return "http://" + url + path
	} else {
		if path == "" {
			return "https://" + url
		}

		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		return "https://" + url + path
	}
}

func ReplaceBody(body map[string]any, key string, value any) (error) {
	_, exist := body[key]
	if !exist {
		return errors.New("Body key not exist")
	}

	body[key] = value

	return nil
}

func ReplacePath(path string, index int, value string) (string , error) {
	paste, err := url.Parse(path)
	if err != nil {
		return "", err
	}

	parts := strings.Split(paste.Path, "/")
	if index < 0 || index >= len(parts) {
		return "", errors.New("Invalid path index")
	}

	parts[index] = value
	paste.Path = strings.Join(parts, "/")

	return paste.RequestURI(), nil
}

func ReplaceQuery(query *url.URL, key string, value string, index int) (string, error) {
	Query := query.Query()

	values, exist := Query[key]
	if !exist {
		return "", errors.New("Query not exist")
	}

	if index < 0 || index >= len(values) {
		return "", errors.New("Invalid query index")
	}


	values[index] = value
	Query[key] = values
	query.RawQuery = Query.Encode()

	return query.RequestURI(), nil
}

func IsSucces(status int) bool {
	return status >= 200 && status < 300
}

