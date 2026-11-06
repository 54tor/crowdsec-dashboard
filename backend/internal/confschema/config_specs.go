package confschema

var mainConfigSpec = withRequired(mainConfigOverrideSpec, "common", "config_paths", "api")

var mainConfigOverrideSpec = mapping(map[string]spec{
	"common":           commonSpec,
	"config_paths":     configPathsSpec,
	"crowdsec_service": crowdsecServiceSpec,
	"cscli":            cscliSpec,
	"db_config":        dbConfigSpec,
	"api":              apiSpec,
	"prometheus":       prometheusSpec,
	"plugin_config":    pluginConfigSpec,
})

func withRequired(base spec, requiredKeys ...string) spec {
	base.required = requiredKeys
	return base
}

var commonSpec = mapping(map[string]spec{
	"daemonize":        boolValue,
	"pid_dir":          stringValue,
	"log_media":        stringValue,
	"log_level":        stringValue,
	"log_dir":          stringValue,
	"working_dir":      stringValue,
	"log_max_size":     intValue,
	"log_max_age":      intValue,
	"log_max_files":    intValue,
	"compress_logs":    boolValue,
	"log_format":       stringValue,
	"force_color_logs": boolValue,
})

var configPathsSpec = mapping(map[string]spec{
	"config_dir":       stringValue,
	"data_dir":         stringValue,
	"simulation_path":  stringValue,
	"hub_dir":          stringValue,
	"index_path":       stringValue,
	"notification_dir": stringValue,
	"plugin_dir":       stringValue,
	"pattern_dir":      stringValue,
})

var crowdsecServiceSpec = mapping(map[string]spec{
	"enable":               boolValue,
	"acquisition_path":     stringValue,
	"acquisition_dir":      stringValue,
	"console_context_path": stringValue,
	"parser_routines":      intValue,
	"buckets_routines":     intValue,
	"output_routines":      intValue,
	"bucket_state_file":    stringValue,
	"bucket_state_dir":     stringValue,
	"state_output_file":    stringValue,
	"disable_ocsf":         boolValue,
})

var pluginConfigSpec = mapping(map[string]spec{
	"user":  anyValue,
	"group": stringValue,
})

var cscliSpec = mapping(map[string]spec{
	"output":         stringValue,
	"color":          stringValue,
	"hub_branch":     stringValue,
	"prometheus_uri": stringValue,
})

var prometheusSpec = mapping(map[string]spec{
	"enabled":     boolValue,
	"level":       stringValue,
	"listen_addr": stringValue,
	"listen_port": intValue,
})

var dbFlushSpec = mapping(map[string]spec{
	"max_items":       intValue,
	"max_age":         stringValue,
	"metrics_max_age": stringValue,
	"bouncers_autodelete": mapping(map[string]spec{
		"cert":    stringValue,
		"api_key": stringValue,
	}),
	"agents_autodelete": mapping(map[string]spec{
		"cert":           stringValue,
		"login_password": stringValue,
	}),
})

var dbConfigSpec = mapping(map[string]spec{
	"type":               stringValue,
	"db_path":            stringValue,
	"use_wal":            boolValue,
	"user":               anyValue,
	"password":           anyValue,
	"db_name":            anyValue,
	"host":               stringValue,
	"port":               intValue,
	"sslmode":            stringValue,
	"ssl_ca_cert":        stringValue,
	"ssl_client_cert":    stringValue,
	"ssl_client_key":     stringValue,
	"max_open_conns":     intValue,
	"decision_bulk_size": intValue,
	"flush":              dbFlushSpec,
})

var apiSpec = mapping(map[string]spec{
	"cti":    apiCTISpec,
	"client": apiClientSpec,
	"server": apiServerSpec,
})

var apiCTISpec = mapping(map[string]spec{
	"key":           anyValue,
	"cache_timeout": stringValue,
	"cache_size":    intValue,
	"enabled":       boolValue,
	"log_level":     stringValue,
})

var apiClientSpec = mapping(map[string]spec{
	"insecure_skip_verify": boolValue,
	"credentials_path":     stringValue,
	"unregister_on_exit":   boolValue,
})

var apiServerTLSSpec = mapping(map[string]spec{
	"cert_file":           stringValue,
	"key_file":            stringValue,
	"client_verification": stringValue,
	"ca_cert_path":        stringValue,
	"agents_allowed_ou":   stringList,
	"bouncers_allowed_ou": stringList,
	"crl_path":            stringValue,
	"cache_expiration":    stringValue,
})

var apiServerSpec = mapping(map[string]spec{
	"enable":                           boolValue,
	"log_level":                        stringValue,
	"listen_uri":                       stringValue,
	"listen_socket":                    stringValue,
	"profiles_path":                    stringValue,
	"use_forwarded_for_headers":        boolValue,
	"console_path":                     stringValue,
	"disable_remote_lapi_registration": boolValue,
	"disable_usage_metrics_export":     boolValue,
	"capi_whitelists_path":             stringValue,
	"trusted_ips":                      stringList,
	"tls":                              apiServerTLSSpec,
	"online_client": mapping(map[string]spec{
		"sharing":          boolValue,
		"credentials_path": stringValue,
		"pull": mapping(map[string]spec{
			"community":  boolValue,
			"blocklists": boolValue,
		}),
	}),
	"auto_registration": mapping(map[string]spec{
		"enabled":        boolValue,
		"token":          anyValue,
		"allowed_ranges": stringList,
	}),
})
