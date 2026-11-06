package confschema

type kind int

const (
	kindAny kind = iota
	kindString
	kindBool
	kindInt
	kindMapping
	kindSequence
)

type spec struct {
	kind         kind
	fields       map[string]spec
	item         *spec
	required     []string
	warnRequired []string
	soft         bool
}

var (
	anyValue    = spec{kind: kindAny}
	stringValue = spec{kind: kindString}
	boolValue   = spec{kind: kindBool}
	intValue    = spec{kind: kindInt}
	openMapping = spec{kind: kindMapping}
)

func mapping(fields map[string]spec, required ...string) spec {
	return spec{kind: kindMapping, fields: fields, required: required}
}

func sequenceOf(item spec) spec {
	return spec{kind: kindSequence, item: &item}
}

var stringList = sequenceOf(stringValue)

func (base spec) withWarnRequired(keys ...string) spec {
	base.warnRequired = keys
	return base
}

func (base spec) asSoft() spec {
	base.soft = true
	return base
}
