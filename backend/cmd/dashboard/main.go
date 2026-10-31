package main

import (
	"log"
	"net/http"
	"os"

	"crowdsec-dashboard/internal/api"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/webui"
)

func main() {
	loadedConfig, loadError := config.Load(os.Getenv)
	if loadError != nil {
		log.Fatal(loadError)
	}

	router := http.NewServeMux()
	router.Handle("GET /api/healthz", api.HealthHandler())
	router.Handle("/", webui.Handler())

	log.Printf("listening on %s", loadedConfig.ListenAddr)
	log.Fatal(http.ListenAndServe(loadedConfig.ListenAddr, router))
}
