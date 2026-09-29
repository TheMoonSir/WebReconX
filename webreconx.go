package main

/**

: Note for myself, new to golang :
We can import mulit by doing import ("package","package/folder")
For errors use package "errors" and on function you need to add func function() (string,error), you can return string,nil or string,errors.New("message")
if we see a error "declared and not used: example" mean we didn't used it.
:= operator is a shortcut for declaring and initializing a variable in one line

strings.Contains is for finding inside something you want to looking for. but its will search if inside there for example "test"

: Project :
Our project is building a tool that would scan when input file for example "example.txt" and inside is:
[HTTP Method] [Path]
[Headers]

[Data if exist]

and check if could've any vuln exist.

The reason is why i dont use python because its slower as fuck :break_heart:

Sorry python.

**/

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"regexp"
	"encoding/base64"

	"github.com/golang-jwt/jwt/v5"
	
)

var (
	File *string
)

func getobjects(file string) (map[string]any, error) {
	result := map[string]any{}

	if file == "example.txt" || file == "" || !strings.Contains(strings.ToLower(file), ".txt") {
		return result, errors.New("Invalid scan value.")
	}

	zfile, err := os.Stat(file);

	if zfile.IsDir() {
		return result, errors.New("Invalid input, input is folder.") 
	}

	if errors.Is(err, os.ErrNotExist) {
		return result, errors.New("Invalid file not exist.")
	}

	data, err := os.ReadFile(file)

	if err != nil {
		return result, err
	}

	content := string(data)
	lines := strings.Split(content, "\n")
	request := strings.Fields(strings.TrimSpace(lines[0]))

	if len(request) < 3 {
		return result, errors.New("Invalid request")
	}

	/**

	// request[0] = HTTP Method
	// request[1] = Path
	// request[2] = Protoal

	Method := request[0]
	Path := request[1]
	Protoal := request[2]


	fmt.Printf("Method: %v\n", Method)
	fmt.Printf("Path: %v\n", Path)
	fmt.Printf("Protoal: %v\n", Protoal)


	**/

	Headers := map[string]string{}
	Start := -1

	for i, word := range lines[1:] {
		if strings.TrimSpace(word) == "" {
			Start = i + 2 
			break
		}

		part := strings.SplitN(word, ":", 2)
		if len(part) != 2 {
			continue
		}

		key := strings.TrimSpace(part[0])
		value := strings.TrimSpace(part[1])

		Headers[key] = value
	}

	// fmt.Printf("%v\n", Headers["Accept"])

	BodyDataEncode := map[string]any{}
	BodyTypeDataEncode := ""

	if Start != -1 && Start < len(lines) {
		body := strings.TrimSpace(strings.Join(lines[Start:], "\n"))

		if strings.HasPrefix(body, "{") {
			err := json.Unmarshal([]byte(body), &BodyDataEncode)
			if err != nil {
				return result, err
			}

			BodyTypeDataEncode = "json"
		} else if strings.HasPrefix(body, "[") {
			var array []map[string]any

			err := json.Unmarshal([]byte(body), &array)
			if err != nil {
				return result, err
			}

			for _, obj := range array {
				for key, value := range obj {
					BodyDataEncode[key] = value
				}
			}

			BodyTypeDataEncode = "json"
		} else {
			for _, b := range strings.Split(body, "&") {
				part := strings.SplitN(b, "=", 2)
				if len(part) != 2 {
					continue
				}

				key := strings.TrimSpace(part[0])
				value := strings.TrimSpace(part[1])

				BodyDataEncode[key] = value
			}

			BodyTypeDataEncode = "form"
		}
	}

	// fmt.Printf("%v\n", BodyDataEncode["wow"])

	result["Method"] = request[0]
	result["Path"] = request[1]
	result["Protoal"] = request[2]
	result["Headers"] = Headers
	result["Data"] = BodyDataEncode
	result["DataType"] = BodyTypeDataEncode

	return result, nil
}

func JwtDecode(token string) (map[string]any, error) {
	result := map[string]any{}
	
	if token == "" {
		fmt.Print("JWT token not fill.")
		return result, nil
	}

	parsedToken, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
        return []byte("a-string-secret-at-least-256-bits-long"), nil
    })

	if !parsedToken.Valid {
		result["Header"] = parsedToken.Header
		result["Data"] = parsedToken.Claims
		result["Vaild"] = false
		return result, nil
	} else {
		result["Header"] = parsedToken.Header
		result["Data"] = parsedToken.Claims
		result["Vaild"] = true
		return result, nil
	}
}

// Would've easier to make function instand always write it again

func createNewRequest(method string, requestURL string, body io.Reader, headers map[string]string,
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


func checktype(value string) string {
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

func checktypedata(data map[string]any, datatype string) (io.Reader, error) {
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

func createAttackID(value string) string {
	idtype := checktype(value)

	switch idtype {
	case "number":
		id, err := strconv.Atoi(value)
		if err != nil {
			return ""
		}

		println("number")

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

// IDOR attack only basic.
// Its support : base64, UUID v4, number, string
// Target only: Path, Url Form, Body Form/Json

// Target Payload curren: "id","user_id","ID","user_ID","uuid","document","user"


func IdorAttack(data map[string]any) (map[string]any, error) {
	result := map[string]any{}
	result["Found"] = false
	KnownCommon := []string{"id","user_id","ID","user_ID","uuid","document","user"}
	fmt.Printf("[!] The IDOR attack only scan - %v\n", KnownCommon)

	if len(data) == 0 {
		return result, errors.New("Invalid data")
	}

	Headers, ok := data["Headers"].(map[string]string)
	if !ok {
		return result, errors.New("Invalid Headers")
	}

	if Headers["Authorization"] == "" && Headers["Cookie"] == "" {
		return result, errors.New("Invalid Auth, User is not Auth")
	}

	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}

	client := &http.Client{
		Transport: tr,
	}

	Method := data["Method"].(string)
	if Method == "" {
		return result, errors.New("Invalid Method")
	}

	body, ok := data["Data"].(map[string]any)
	if !ok {
		return result, errors.New("Invalid body")
	}

	DataType := data["DataType"].(string)
	
	// IDOR based data body

	for _, key := range KnownCommon {
		value, exist := body[key]
		if !exist {
			continue
		}

		MainID := fmt.Sprint(value)

		AttackID := createAttackID(MainID)

		if len(AttackID) == 0 {
			continue
		}

		body[key] = AttackID

		BodyEncode, err := checktypedata(body, DataType)
		if err != nil {
			continue
		}

		requestURL := fmt.Sprintf("http://%v", Headers["Host"]) // for testing
		//requestURL := fmt.Sprintf("https://%v", Headers["Host"]) // real target
		req , err := createNewRequest(Method, requestURL, BodyEncode, Headers)

		if err != nil {
			return result, err
		}

		fmt.Printf("Main ID - %v\n", MainID)
		fmt.Printf("Attack ID - %v\n", AttackID)

		res, err := client.Do(req)

		if err != nil {
			return result, err
		}

		body[key] = MainID

		if res.StatusCode >= 200 {
			result["Found"] = true
			result["Payload"] = key
			result["MainID"] = MainID
			result["AttackID"] = AttackID
			result["Status"] = res.StatusCode
		}
	}

	// IDOR based path

	Path, ok := data["Path"].(string)
	if !ok {
		return result, errors.New("Invalid Path")
	}

	if Path != "" && result["Found"].(bool) {
		parts := strings.Split(Path, "/")

		for i, part := range parts {
			if part == "" { continue }

			idtype := checktype(part)
			
			if idtype == "string" {
				continue
			}

			AttackID := createAttackID(part)

			if len(AttackID) == 0 {
				continue
			}

			attackpart := make([]string, len(parts))
			copy(attackpart, parts)

			mainpath := strings.Join(attackpart, "/")

			attackpart[i] = AttackID

			attackpath := strings.Join(attackpart, "/")

			fmt.Printf("Main Path - %v\n", mainpath)
			fmt.Printf("Attack Path - %v\n", attackpath)

			requestURL := fmt.Sprintf("http://%v%s", Headers["Host"], attackpath) // for testing
			//requestURL := fmt.Sprintf("https://%v/%v", Headers["Host"], attackpath) // real target
			req , err := createNewRequest(Method, requestURL, nil, Headers)

			if err != nil {
				return result, err
			}

			res, err := client.Do(req)

			if err != nil {
				return result, err
			}

			if res.StatusCode >= 200 {
				result["Found"] = true
				result["Payload"] = attackpath
				result["MainID"] = part
				result["AttackID"] = AttackID
				result["Status"] = res.StatusCode
			}
		}
	}

	// IDOR based Url form
	q, err := url.Parse(Path)
	if err != nil {
		return result, err
	}

	query := q.Query()

	for _, key := range KnownCommon {
		values, exist := query[key]
		if !exist {
			continue
		}

		for i, value := range values {
			MainID := fmt.Sprint(value)

			AttackID := createAttackID(MainID)

			if len(AttackID) == 0 {
				continue
			}

			query[key][i] = AttackID

			q.RawQuery = query.Encode()

			requestURL := fmt.Sprintf("http://%v%s", Headers["Host"], q.RequestURI()) // for testing
			//requestURL := fmt.Sprintf("https://%v%s", Headers["Host"]) // real target
			req , err := createNewRequest(Method, requestURL, nil, Headers)

			if err != nil {
				return result, err
			}

			fmt.Printf("Main ID - %v\n", MainID)
			fmt.Printf("Attack ID - %v\n", AttackID)

			res, err := client.Do(req)

			if err != nil {
				return result, err
			}

			query[key][i] = MainID

			q.RawQuery = query.Encode()

			if res.StatusCode >= 200 {
				result["Found"] = true
				result["Payload"] = key
				result["MainID"] = MainID
				result["AttackID"] = AttackID
				result["Status"] = res.StatusCode
			}
		}
	}



	return result, nil
}





func init() {
	File = flag.String("scan", "example.txt", "scan request you want and analaying if possible for bug.")
}

func main() {
	flag.Parse()

	data, err := getobjects(*File)

	if err != nil {
		fmt.Printf("Error happen in [getobject], msg: %s", err)
		return
	}

	Headers := data["Headers"].(map[string]string)
	fmt.Printf("Target: %v%s\n", Headers["Host"], data["Path"])

	xr, err := IdorAttack(data)
	if err != nil {
		fmt.Printf("Error happen in [IdorAttack], msg: %s", err)
		return
	}

	fmt.Printf("%v\n", xr)

	/**

	This will let us see what the body return, because we see hex :broken_heart:

	var da map[string]any

	bd, err := io.ReadAll(req.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	errs := json.Unmarshal(bd, &da)
	if errs != nil {
		fmt.Println(err)
		return
	}


	fmt.Println(da["wow"])
	**/

	


}	
