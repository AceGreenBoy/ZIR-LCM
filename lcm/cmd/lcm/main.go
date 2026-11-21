// lcm (ZIR LifecycleManager): admin UI and device API in one process.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"zir/lcm/internal/config"
	"zir/lcm/internal/core"
	"zir/lcm/internal/db"
	"zir/lcm/internal/httpapi"
	"zir/lcm/internal/signer"
	"zir/lcm/internal/web"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	env, err := config.LoadMasterKey(cfg.MasterKeyFile)
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	s, err := signer.Load(ctx, pool, env)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return err
	}
	c := core.New(pool, s, env, cfg.DataDir)

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(requestLog)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := pool.Ping(r.Context()); err != nil {
			http.Error(w, "db down", 503)
			return
		}
		w.Write([]byte("ok"))
	})
	r.Mount("/dev/v1", (&httpapi.API{Core: c}).Routes())
	r.Mount("/", web.New(c, cfg.InsecureCookie, cfg.PublicURL).Routes())

	srv := &http.Server{Addr: cfg.Listen, Handler: r, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 2 * time.Minute, WriteTimeout: 5 * time.Minute, IdleTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	slog.Info("listening", "addr", cfg.Listen, "public_url", cfg.PublicURL)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// requestLog logs method, path, status and duration; never bodies or tokens.
func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		if r.URL.Path == "/healthz" || len(r.URL.Path) > 7 && r.URL.Path[:8] == "/static/" {
			return
		}
		slog.Info("http", "method", r.Method, "path", r.URL.Path, "status", ww.Status(),
			"ms", time.Since(start).Milliseconds(), "ip", httpapi.ClientIP(r))
	})
}
