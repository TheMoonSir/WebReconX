package unit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type RequestData struct {
	Method string
	Path string
	Headers map[string]string
	Body map[string]any
	DataType string
}

func Checktype(value string) string {
	_, err := strconv.Atoi(value)
	if err == nil {
		return "number"
	}

	// Check if string is base64
	// https://stackoverflow.com/questions/15334220/encode-decode-base64
	d, err := base64.StdEncoding.DecodeString(value)
	if err == nil && base64.StdEncoding.EncodeToString(d) == value {
		return "base64"
	}


	// For all who wonder how would you check the string if he UUID 
	// https://stackoverflow.com/questions/25051675/how-to-validate-uuid-v4-in-go

	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
    if r.MatchString(value) {
		return "uuid"
	}

	return "string"
}

func Checktypedata(data map[string]any, datatype string) (io.Reader, error) {
	switch datatype {
	case "json":
		jsdata, err := json.Marshal(data)
		if err != nil { 
			return nil, err
		}

		return bytes.NewReader(jsdata), nil
	case "form":
		form := url.Values{}

		for key,value := range data {
			form.Set(key, fmt.Sprint(value))
		}

		return strings.NewReader(form.Encode()), nil
	}

	return nil, errors.New("Invalid Data Type")
}

func CheckBody(body map[string]any, payloads []string) (map[string]any) {
	result := map[string]any{}

	for _, key := range payloads {
		if value, exist := body[key]; exist {
			result[key] = value
		}
	}

	return result
}

func CheckQuery(path string, payloads []string) (map[string][]string, *url.URL) {
	q, err := url.Parse(path)
	if err != nil {
		return nil, nil
	}

	Query := q.Query()
	result := map[string][]string{}

	for _, key := range payloads {
		if values, exists := Query[key]; exists {
			result[key] = values
		}
	}

	return result, q
}

func CheckPath(path string) (map[int]string, error) {
	q, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(q.Path, "/")
	result := map[int]string{}

	for i, part := range parts {
		if part == "" {
			continue
		}

		result[i] = part
	}

	return result, nil
}

func CreateAttackID(value string) (string) {
	idtype := Checktype(value)

	switch idtype {
	case "number":
		id, err := strconv.Atoi(value)
		if err != nil {
			return ""
		}

		return strconv.Itoa(id + 1)
	case "uuid":
		id := []byte(value)

		for i := len(id) -1; i >= 0; i-- {
			if id[i] == '-' {
				continue
			}

			if id[i] != 'f' {
				id[i] = 'f'
			} else {
				id[i] = 'e'
			}

			break
		}

		return string(id)
	case "base64":
		d, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return ""
		}

		decodevalue := string(d)

		id , err := strconv.Atoi(decodevalue)
		if err != nil {
			return ""
		}

		modifie := strconv.Itoa(id + 1)

		return base64.StdEncoding.EncodeToString([]byte(modifie))
	case "string":
		re := regexp.MustCompile(`^(.*?)(\d+)$`)
		match := re.FindStringSubmatch(value)

		if len(match) == 3 {
			id, err := strconv.Atoi(match[2])
			if err == nil {
				return match[1] + strconv.Itoa(id+1)
			}
		}


		return value + "1"
	}

	return ""
}

func VaildRequest(data map[string]any) (RequestData, error) {
	if len(data) == 0 {
		return RequestData{}, errors.New("Invalid data")
	}

	headers, ok := data["Headers"].(map[string]string)
	if !ok {
		return RequestData{}, errors.New("Invalid Headers")
	}

	if headers["Authorization"] == "" && headers["Cookie"] == "" {
		return RequestData{}, errors.New("Invalid Auth, User is not Auth")
	}

	method := data["Method"].(string)
	if method == "" {
		return RequestData{}, errors.New("Invalid Method")
	}

	path, ok := data["Path"].(string)
	if !ok {
		return RequestData{}, errors.New("Invalid Path")
	}

	body, ok := data["Data"].(map[string]any)
	if !ok {
		return RequestData{}, errors.New("Invalid body")
	}

	datatype, ok := data["DataType"].(string)
	if !ok {
		return RequestData{}, errors.New("Invalid DataType")
	}

	return RequestData{
		Method: method,
		Headers: headers,
		Body: body,
		Path: path,
		DataType: datatype,
	}, nil
}