package confschema

var acquisitionGenericFields = map[string]spec{
	"source":           stringValue,
	"labels":           openMapping,
	"log_level":        stringValue,
	"use_time_machine": boolValue,
	"transform":        stringValue,
}

var acquisitionSourceFields = map[string]map[string]spec{
	"file": {
		"filename":             stringValue,
		"filenames":            stringList,
		"exclude_regexps":      stringList,
		"mode":                 stringValue,
		"poll_without_inotify": boolValue,
		"force_inotify":        boolValue,
		"discover_on_inotify":  boolValue,
	},
	"journalctl": {
		"journalctl_filter": stringList,
		"since":             stringValue,
	},
	"docker": {
		"container_name":        stringList,
		"container_id":          stringList,
		"container_name_regexp": stringList,
		"container_id_regexp":   stringList,
		"docker_host":           stringValue,
		"use_container_labels":  boolValue,
		"check_interval":        stringValue,
		"since":                 stringValue,
		"until":                 stringValue,
		"follow_stdout":         boolValue,
		"follow_stderr":         boolValue,
	},
	"kafka": {
		"brokers":   stringList,
		"topic":     stringValue,
		"group_id":  stringValue,
		"timeout":   stringValue,
		"tls":       openMapping,
		"auth_type": stringValue,
	},
	"cloudwatch": {
		"aws_profile":                  stringValue,
		"aws_region":                   stringValue,
		"aws_config_dir":               stringValue,
		"aws_api_timeout":              stringValue,
		"log_group_name":               stringValue,
		"log_stream_name":              stringValue,
		"log_group_name_regexp":        stringValue,
		"stream_regexp":                stringValue,
		"stream_name":                  stringValue,
		"prefix":                       stringValue,
		"max_stream_age":               stringValue,
		"poll_new_stream_interval":     stringValue,
		"poll_stream_interval":         stringValue,
		"getlogeventspagination":       intValue,
		"describelogstreams_limit":     intValue,
		"describelogstreams_pagelimit": intValue,
		"getlogeventsinterval":         stringValue,
		"backlog_duration":             stringValue,
	},
	"syslog": {
		"listen_addr":     stringValue,
		"listen_port":     intValue,
		"listen_socket":   stringValue,
		"protocol":        stringValue,
		"max_message_len": intValue,
	},
	"k8s-audit": {
		"listen_addr":  stringValue,
		"listen_port":  intValue,
		"webhook_path": stringValue,
	},
	"kubernetes": {
		"namespace":      stringValue,
		"selector":       stringValue,
		"pod_name":       stringValue,
		"kube_config":    stringValue,
		"kube_context":   stringValue,
		"container_name": stringValue,
	},
	"appsec": {
		"listen_addr":         stringValue,
		"listen_socket":       stringValue,
		"path":                stringValue,
		"appsec_config":       stringValue,
		"appsec_configs":      stringList,
		"appsec_config_path":  stringValue,
		"auth_cache_duration": stringValue,
		"cert_file":           stringValue,
		"key_file":            stringValue,
		"routines":            intValue,
	},
}

var acquisitionSpec = mapping(mergeAcquisitionFields(), "source")

func mergeAcquisitionFields() map[string]spec {
	mergedFields := map[string]spec{}
	for fieldName, fieldSpec := range acquisitionGenericFields {
		mergedFields[fieldName] = fieldSpec
	}
	for _, sourceFields := range acquisitionSourceFields {
		for fieldName, fieldSpec := range sourceFields {
			existingSpec, alreadyDeclared := mergedFields[fieldName]
			if alreadyDeclared && existingSpec.kind != fieldSpec.kind {
				mergedFields[fieldName] = anyValue
				continue
			}
			mergedFields[fieldName] = fieldSpec
		}
	}
	return mergedFields
}
