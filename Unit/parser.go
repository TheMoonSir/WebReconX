package unit

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

)

var (
	File *string
)

func ParseDataFromFile(file string) (map[string]any, error) {
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
