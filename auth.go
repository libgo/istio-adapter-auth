// nolint:lll
// Generates the auth adapter's resource yaml. It contains the adapter's configuration, name,
// supported template names (metric in this case), and whether it is session or no-session based.
//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -t mixer/adapter/auth/template.proto
//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -a mixer/adapter/auth/config/config.proto -x "-s=false -n auth-adapter -t auth"

package auth

import (
	"context"
	"fmt"
	"net"
	strings "strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcs "google.golang.org/grpc/status"
	"istio.io/api/mixer/adapter/model/v1beta1"
	policy "istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/adapter/auth/config"
	"istio.io/istio/mixer/adapter/auth/jwt"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/istio/pkg/log"
)

type (
	// Server is basic server interface
	Server interface {
		Addr() string
		Close() error
		Run(shutdown chan error)
	}

	// AuthAdapter supports authorization template.
	AuthAdapter struct {
		listener net.Listener
		server   *grpc.Server
	}
)

// impl check
var _ HandleAuthServiceServer = &AuthAdapter{}

// HandleAuth impl
// Steps:
func (s *AuthAdapter) HandleAuth(ctx context.Context, r *HandleAuthRequest) (*HandleAuthResponse, error) {
	cfg := &config.Params{}
	if r.AdapterConfig != nil {
		if err := cfg.Unmarshal(r.AdapterConfig.Value); err != nil {
			log.Errorf("error unmarshalling adapter config: %v", err)
			return nil, grpcs.Error(codes.Internal, err.Error())
		}
	}

	decodeValue := func(in interface{}) interface{} {
		switch t := in.(type) {
		case *policy.Value_StringValue:
			return t.StringValue
		case *policy.Value_Int64Value:
			return t.Int64Value
		case *policy.Value_DoubleValue:
			return t.DoubleValue
		default:
			return fmt.Sprintf("%v", in)
		}
	}

	decodeValueMap := func(in map[string]*policy.Value) map[string]interface{} {
		out := make(map[string]interface{}, len(in))
		for k, v := range in {
			out[k] = decodeValue(v.GetValue())
		}
		return out
	}

	props := decodeValueMap(r.Instance.Subject.Properties)

	// skip if has x-token-verify header
	if xAuth, ok := props["x-token-verify"].(string); ok && xAuth == "1" {
		return &HandleAuthResponse{
			Result: &v1beta1.CheckResult{
				Status:        status.OK,
				ValidDuration: time.Second * time.Duration(cfg.ValidDurationSec),
				ValidUseCount: cfg.ValidUseCount,
			},
		}, nil
	}

	// jwt check and validate
	xToken, ok := props["x-token"].(string)
	if !ok {
		return &HandleAuthResponse{
			Result: &v1beta1.CheckResult{Status: status.WithUnauthenticated("missing token")},
		}, nil
	}

	// trim prefix `Bearer `
	xToken = strings.TrimPrefix(xToken, "Bearer ")

	c := jwt.Claims{}
	err := jwt.Parse(xToken, &c)
	if err != nil {
		return &HandleAuthResponse{
			Result: &v1beta1.CheckResult{Status: status.WithUnauthenticated(err.Error())},
		}, nil
	}

	// TODO rbac

	// set x-token-verify: 1
	outputMsg := &OutputMsg{
		Headers: map[string]string{"x-token-verify": "1"},
	}

	// token refresh
	if c.NeedRefresh() {
		c.Refresh()
		outputMsg.Headers["x-token"] = c.Sign()
	}

	return &HandleAuthResponse{
		Result: &v1beta1.CheckResult{
			Status:        status.OK,
			ValidDuration: time.Second * time.Duration(cfg.ValidDurationSec),
			ValidUseCount: cfg.ValidUseCount,
		},
		Output: outputMsg,
	}, nil

}

// Addr returns the listening address of the server
func (s *AuthAdapter) Addr() string {
	return s.listener.Addr().String()
}

// Run starts the server run
func (s *AuthAdapter) Run(shutdown chan error) {
	shutdown <- s.server.Serve(s.listener)
}

// Close gracefully shuts down the server; used for testing
func (s *AuthAdapter) Close() error {
	if s.server != nil {
		s.server.GracefulStop()
	}

	if s.listener != nil {
		_ = s.listener.Close()
	}

	return nil
}

var version = "none"

// NewAuthAdapter creates a new IBP adapter that listens at provided port.
func NewAuthAdapter(addr string) (Server, error) {
	if addr == "" {
		addr = "0"
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", addr))
	if err != nil {
		return nil, fmt.Errorf("unable to listen on socket: %v", err)
	}

	s := &AuthAdapter{
		listener: listener,
	}

	log.Infof("listening on \"%v\" ver:%s\n", s.Addr(), version)

	s.server = grpc.NewServer()
	RegisterHandleAuthServiceServer(s.server, s)
	return s, nil
}
