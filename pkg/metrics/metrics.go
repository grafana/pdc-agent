package metrics

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	httpServer *http.Server
	logger     log.Logger
}

func NewMetricsServer(logger log.Logger, port int) *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	return &Server{
		logger: logger,
		httpServer: &http.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Handler: mux,
		},
	}
}

func (s *Server) Run() {
	level.Info(s.logger).Log("msg", "starting serving metrics on port "+s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		level.Info(s.logger).Log("msg", "failed to run metrics server", "err", err)
	}
}
