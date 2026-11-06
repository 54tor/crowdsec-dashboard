package confschema

var whitelistSpec = mapping(map[string]spec{
	"name":           stringValue,
	"description":    stringValue,
	"filter":         stringValue,
	"debug":          boolValue,
	"onsuccess":      stringValue,
	"data":           anyValue,
	"statics":        anyValue,
	"nodes":          anyValue,
	"pattern_syntax": openMapping,
	"whitelist": mapping(map[string]spec{
		"reason":     stringValue,
		"ip":         stringList,
		"cidr":       stringList,
		"expression": stringList,
	}).withWarnRequired("reason"),
}).withWarnRequired("name", "description", "whitelist")
