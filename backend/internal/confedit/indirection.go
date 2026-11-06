package confedit

import (
	"strconv"

	"go.yaml.in/yaml/v3"
)

type indirectionOccurrences struct {
	count     int
	firstLine int
}

func (parsed *parsedText) addIndirection(record string, line int) {
	occurrences, alreadySeen := parsed.indirections[record]
	if !alreadySeen || line < occurrences.firstLine {
		occurrences.firstLine = line
	}
	occurrences.count++
	parsed.indirections[record] = occurrences
}

func (parsed *parsedText) noteIndirection(node *yaml.Node, path string) {
	location := strconv.Quote(path) + "\x00"
	if node.Kind == yaml.AliasNode {
		aliasTarget := ""
		if node.Alias != nil {
			aliasTarget = parsed.masked.node(node.Alias)
		}
		parsed.addIndirection("*"+location+strconv.Quote(node.Value)+"="+aliasTarget, node.Line)
	}
	if node.Anchor != "" {
		parsed.addIndirection("&"+location+strconv.Quote(node.Anchor)+"="+parsed.masked.node(node), node.Line)
	}
}

func (parsed *parsedText) noteMergeKey(identity string, keyNode, valueNode *yaml.Node) {
	if keyNode.Value != "<<" || keyNode.Tag != "!!merge" {
		return
	}
	parsed.addIndirection("<<"+strconv.Quote(identity)+"\x00="+parsed.masked.node(valueNode), keyNode.Line)
}
