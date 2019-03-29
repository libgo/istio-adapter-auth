package main

import (
	"os"

	"istio.io/istio/mixer/adapter/auth"
	"istio.io/istio/pkg/log"
)

func main() {
	addr := ""
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	s, err := auth.NewAuthAdapter(addr)
	if err != nil {
		log.Errorf("unable to start server: %v", err)
		os.Exit(-1)
	}

	shutdown := make(chan error, 1)
	go func() {
		s.Run(shutdown)
	}()
	_ = <-shutdown
}
