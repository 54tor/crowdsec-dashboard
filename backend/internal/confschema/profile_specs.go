package confschema

var profileSpec = mapping(map[string]spec{
	"name":    stringValue,
	"debug":   boolValue,
	"filters": stringList,
	"decisions": sequenceOf(mapping(map[string]spec{
		"type":     stringValue,
		"scope":    stringValue,
		"value":    stringValue,
		"duration": stringValue,
		"origin":   stringValue,
	})),
	"duration_expr": stringValue,
	"notifications": stringList,
	"on_success":    stringValue,
	"on_failure":    stringValue,
}).withWarnRequired("name", "filters")
