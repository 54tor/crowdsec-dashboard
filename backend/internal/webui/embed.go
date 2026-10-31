package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var embeddedFiles embed.FS

const indexFileName = "index.html"

func Handler() http.Handler {
	distFiles, subError := fs.Sub(embeddedFiles, "dist")
	if subError != nil {
		panic(subError)
	}
	return spaHandler(distFiles)
}

func spaHandler(distFiles fs.FS) http.Handler {
	fileServer := http.FileServerFS(distFiles)
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if _, indexError := fs.Stat(distFiles, indexFileName); indexError != nil {
			http.NotFound(responseWriter, request)
			return
		}
		requestedPath := strings.TrimPrefix(path.Clean(request.URL.Path), "/")
		if requestedPath == "" || isRegularFile(distFiles, requestedPath) {
			fileServer.ServeHTTP(responseWriter, request)
			return
		}
		request.URL.Path = "/"
		fileServer.ServeHTTP(responseWriter, request)
	})
}

func isRegularFile(distFiles fs.FS, filePath string) bool {
	fileInfo, statError := fs.Stat(distFiles, filePath)
	return statError == nil && !fileInfo.IsDir()
}
