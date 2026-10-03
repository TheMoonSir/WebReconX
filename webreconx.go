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
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	// Payloads
	"webreconx/Payloads"

	// Units
	"webreconx/Unit"
)


func IdorAttack(data map[string]any) (map[string]any, error) {
	result := map[string]any{}

	requestData, err := unit.VaildRequest(data)
	if err != nil {
		return result, err
	}

	client := unit.CreateClient()

	bodyvalues := unit.CheckBody(requestData.Body, payloads.IDORKnownCommonPayloads)
	pathvalues, err := unit.CheckPath(requestData.Path)
	queryValues, q := unit.CheckQuery(requestData.Path, payloads.IDORKnownCommonPayloads)

	// IDOR based data body

	for key, value := range bodyvalues {
		MainID := fmt.Sprint(value)

		AttackID := unit.CreateAttackID(MainID)
		if AttackID == "" {
			continue
		}

		err := unit.ReplaceBody(requestData.Body, key, AttackID)
		if err != nil {
			continue
		}

		BodyEncode, err := unit.Checktypedata(requestData.Body, requestData.DataType)
		if err != nil {
			unit.ReplaceBody(requestData.Body, key, value)
			continue
		}

		requestURL := unit.BuildUrl(requestData.Headers["Host"], "" , false)
		_, status, _, err := unit.SendRequest(client, requestData.Method, requestURL, BodyEncode, requestData.Headers)

		if err != nil {
			unit.ReplaceBody(requestData.Body, key, value)
			return result, err
		}

		unit.ReplaceBody(requestData.Body, key, value)

		if unit.IsSucces(status) {
			result["Payload"] = key
			result["MainID"] = MainID
			result["AttackID"] = AttackID
			result["Status"] = status

			return result, nil
		}
	}

	// IDOR based path

	for i, part := range pathvalues {		
		if unit.Checktype(part) == "string" {
			continue
		}

		AttackID := unit.CreateAttackID(part)
		if AttackID == "" {
			continue
		}

		AttackPath, err := unit.ReplacePath(requestData.Path, i, AttackID)
		if err != nil {
			continue
		}

		requestURL := unit.BuildUrl(requestData.Headers["Host"], AttackPath, false)
		_, status, _, err := unit.SendRequest(client, requestData.Method, requestURL, nil, requestData.Headers)

		if err != nil {
			unit.ReplacePath(requestData.Path, i, part)
			return result, err
		}

		unit.ReplacePath(requestData.Path, i, part)

		if unit.IsSucces(status) {
			result["Payload"] = AttackPath
			result["MainID"] = part
			result["AttackID"] = AttackID
			result["Status"] = status

			return result, nil
		}
	}

	// IDOR based Url form

	for key, values := range queryValues {
		for i, value := range values {

			MainID := value
			AttackID := unit.CreateAttackID(MainID)

			if len(AttackID) == 0 {
				continue
			}

			attackquery, err := unit.ReplaceQuery(q, key, AttackID, i)
			if err != nil {
				continue
			}

			requestURL := unit.BuildUrl(requestData.Headers["Host"], attackquery, false)
			_, status, _, err := unit.SendRequest(client, requestData.Method, requestURL, nil, requestData.Headers)

			if err != nil {
				unit.ReplaceQuery(q, key, MainID, i)
				return result, err
			}

			if unit.IsSucces(status) {
				result["Payload"] = key
				result["MainID"] = MainID
				result["AttackID"] = AttackID
				result["Status"] = status

				return result, nil
			}
		}
	}
	
	return result, nil
}

func sqliAttack(data map[string]any) (map[string]any, error) {
	result := map[string]any{}

	requestData, err := unit.VaildRequest(data)
	if err != nil {
		return result, err
	}

	client := unit.CreateClient()

	bodyvalues := unit.CheckBody(requestData.Body, payloads.SqliKnownCommonPayloads)
	queryValues, q := unit.CheckQuery(requestData.Path, payloads.SqliKnownCommonPayloads)

	for payloadtype, payload := range payloads.SqliPayloads {
		// Sqli based data body
		for key, value := range bodyvalues {
			MainID := fmt.Sprint(value)

			AttackID := MainID + payload

			err := unit.ReplaceBody(requestData.Body, key, AttackID)
			if err != nil {
				continue
			}

			BodyEncode, err := unit.Checktypedata(requestData.Body, requestData.DataType)
			if err != nil {
				unit.ReplaceBody(requestData.Body, key, value)
				continue
			}

			requestURL := unit.BuildUrl(requestData.Headers["Host"], "" , false)
			_, status, elasped, err := unit.SendRequest(client, requestData.Method, requestURL, BodyEncode, requestData.Headers)

			if err != nil {
				unit.ReplaceBody(requestData.Body, key, value)
				return result, err
			}

			if payloadtype == "Time_Based" {
				unit.ReplaceBody(requestData.Body, key, value)
				
				if elasped >= 5 * time.Second {
					result["Payload"] = key
					result["MainID"] = MainID
					result["AttackID"] = AttackID
					result["Status"] = status
					
					return result, nil
				}
			} else {
				unit.ReplaceBody(requestData.Body, key, value)

				if status >= 500 && status< 600 {
					result["Found"] = true
					result["Payload"] = key
					result["MainID"] = MainID
					result["AttackID"] = AttackID
					result["Status"] = status
					
					return result, nil
				}
			}
		}

		// Sqli based query

		for key, values := range queryValues {
			for i, value := range values {
				MainID := fmt.Sprint(value)
				AttackID := MainID + payload

				attackquery, err := unit.ReplaceQuery(q, key, AttackID, i)
				if err != nil {
					continue
				}

				requestURL := unit.BuildUrl(requestData.Headers["Host"], attackquery, false)
				_, status, elasped, err := unit.SendRequest(client, requestData.Method, requestURL, nil, requestData.Headers)

				if err != nil {
					unit.ReplaceQuery(q, key, MainID, i)
					return result, err
				}


				if payloadtype == "Time_Based" {
					unit.ReplaceQuery(q, key, MainID, i)

					if elasped >= 5 * time.Second  {
						result["Payload"] = key
						result["MainID"] = MainID
						result["AttackID"] = AttackID
						result["Status"] = status

						return result, nil
					}
				} else {
					unit.ReplaceQuery(q, key, MainID, i)

					if status >= 500 && status < 600 {
						result["Payload"] = key
						result["MainID"] = MainID
						result["AttackID"] = AttackID
						result["Status"] = status
						
						return result, nil
					}
				}
			}
		}
	}

	return result, nil
}

func lfiAttack(data map[string]any) (map[string]any, error) {
	result := map[string]any{}

	requestData, err := unit.VaildRequest(data)
	if err != nil {
		return result, err
	}

	client := unit.CreateClient()
	bodyvalues := unit.CheckBody(requestData.Body, payloads.LFIKnownCommonPayloads)
	queryValues, q := unit.CheckQuery(requestData.Path, payloads.LFIKnownCommonPayloads)
	
	// LFI based data body

	for _, payload := range payloads.LFIPayloads {
		for key, value := range bodyvalues {
			MainID := fmt.Sprint(value)
			AttackID := strings.TrimRight(MainID, "/") + "/" + strings.TrimLeft(payload, "/")

			err := unit.ReplaceBody(requestData.Body, key, AttackID)
			if err != nil {
				continue
			}

			BodyEncode, err := unit.Checktypedata(requestData.Body, requestData.DataType)
			if err != nil {
				unit.ReplaceBody(requestData.Body, key, value)
				continue
			}

			requestURL := unit.BuildUrl(requestData.Headers["Host"], "" , false)
			res, status, _, err := unit.SendRequest(client, requestData.Method, requestURL, BodyEncode, requestData.Headers)

			if err != nil {
				return result, err
			}

			resbody, err := io.ReadAll(res.Body)
			if err != nil {
				unit.ReplaceBody(requestData.Body, key, value)
				return result, err
			}

			unit.ReplaceBody(requestData.Body, key, value)
			
			if bytes.Contains(resbody, []byte("Linux version")) {
				result["Payload"] = key
				result["MainID"] = MainID
				result["AttackID"] = AttackID
				result["Status"] = status
				
				return result, nil
			}
		}

		for key, values := range queryValues {
			for i, value := range values {
				MainID := fmt.Sprint(value)
				AttackID := strings.TrimRight(MainID, "/") + "/" + strings.TrimLeft(payload, "/")

				attackquery, err := unit.ReplaceQuery(q, key, AttackID, i)
				if err != nil {
					continue
				}

				requestURL := unit.BuildUrl(requestData.Headers["Host"], attackquery, false)
				res, status, _, err := unit.SendRequest(client, requestData.Method, requestURL, nil, requestData.Headers)

				if err != nil {
					unit.ReplaceQuery(q, key, MainID, i)
					return result, err
				}

				resbody, err := io.ReadAll(res.Body)
				if err != nil {
					unit.ReplaceQuery(q, key, MainID, i)
					return result, err
				}

				if bytes.Contains(resbody, []byte("Linux version")) {
					result["Found"] = true
					result["Payload"] = key
					result["MainID"] = MainID
					result["AttackID"] = AttackID
					result["Status"] = status
					return result, nil
				}
			}
		}
	}

	return result, nil
}

func init() {
	unit.File = flag.String("scan", "example.txt", "scan request you want and analaying if possible for bug.")
}

func main() {
	flag.Parse()

	data, err := unit.ParseDataFromFile(*unit.File)

	if err != nil {
		fmt.Printf("Error happen in [ParseDataFromFile], msg: %s", err)
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
