package middlewares

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
)

type CompressionConfig struct {
	ExcludePaths     map[string]bool
	ExcludeTypes     []string
	CompressionLevel int
}

func DefaultCompressionConfig() *CompressionConfig {
	return &CompressionConfig{
		ExcludePaths: map[string]bool{
			"/download": true,
		},
		ExcludeTypes: []string{
			"image/",
			"video/",
			"audio/",
			"application/zip",
			"application/gzip",
			"application/octet-stream",
		},
		CompressionLevel: gzip.BestSpeed,
	}
}

type GzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
	contentTypeChecked bool
	config             *CompressionConfig
}

func (w *GzipResponseWriter) Write(b []byte) (int, error) {
	if !w.contentTypeChecked {
		w.contentTypeChecked = true
		contentType := w.Header().Get("Content-Type")
		for _, excludeType := range w.config.ExcludeTypes {
			if strings.Contains(contentType, excludeType) {
				return w.ResponseWriter.Write(b)
			}
		}
	}
	return w.Writer.Write(b)
}
func (w *GzipResponseWriter) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}
func (w *GzipResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}
func CompressionMiddleware(config *CompressionConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = DefaultCompressionConfig()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if config.ExcludePaths[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Vary", "Accept-Encoding")
			gz, err := gzip.NewWriterLevel(w, config.CompressionLevel)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			defer gz.Close()
			gzw := &GzipResponseWriter{
				Writer:         gz,
				ResponseWriter: w,
				config:         config,
			}
			next.ServeHTTP(gzw, r)
		})
	}
}
