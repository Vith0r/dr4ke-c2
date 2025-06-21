package middlewares

import (
	"dr4ke-c2/server/utils"
	"net/http"
	"time"
)

type LoggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *LoggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &LoggingResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}
		next.ServeHTTP(lrw, r)
		duration := time.Since(start)
		contentType := lrw.Header().Get("Content-Type")
		utils.LogOutput("[%s] %s %s -> %d %s (%s)",
			r.Method,
			r.RemoteAddr,
			r.URL.Path,
			lrw.statusCode,
			duration,
			contentType)
	})
}
