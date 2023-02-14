package oauthutil

import (
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/gorilla/mux"
	"github.com/jlewi/p22h/backend/api"
	"github.com/jlewi/p22h/backend/pkg/debug"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"time"
)

// OIDCWebFlowServer creates a server to be used to go through the web flow to get a token source
// for use in a CLI.
//
// It is based on the code in https://github.com/coreos/go-oidc/blob/v3/example/idtoken/app.go.
//
// N.B: https://github.com/coreos/go-oidc/issues/354 is discussing creating a reusable server.
//
// TODO(jeremy): Add caching of the refresh token.
type OIDCWebFlowServer struct {
	log      logr.Logger
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
	host     string
	c        chan tokenSourceOrError
	srv      *http.Server
}

func NewOIDCWebFlowServer(config oauth2.Config, verifier *oidc.IDTokenVerifier, log logr.Logger) (*OIDCWebFlowServer, error) {
	u, err := url.Parse(config.RedirectURL)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not parse URL %v", config.RedirectURL)
	}

	return &OIDCWebFlowServer{
		log:      log,
		config:   config,
		verifier: verifier,
		host:     u.Host,
		c:        make(chan tokenSourceOrError, 10),
	}, nil
}

func (s *OIDCWebFlowServer) Address() string {
	return fmt.Sprintf("http://%v", s.host)
}

// AuthStartURL returns the URL to kickoff the oauth login flow.
func (s *OIDCWebFlowServer) AuthStartURL() string {
	return s.Address() + authStartPrefix
}

func (s *OIDCWebFlowServer) writeStatus(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	resp := api.RequestStatus{
		Kind:    "RequestStatus",
		Message: message,
		Code:    code,
	}

	enc := json.NewEncoder(w)
	if err := enc.Encode(resp); err != nil {
		s.log.Error(err, "Failed to marshal RequestStatus", "RequestStatus", resp, "code", code)
	}

	if code != http.StatusOK {
		caller := debug.ThisCaller()
		s.log.Info("HTTP error", "RequestStatus", resp, "code", code, "caller", caller)
	}
}

func (s *OIDCWebFlowServer) HealthCheck(w http.ResponseWriter, r *http.Request) {
	s.writeStatus(w, "OIDC server is running", http.StatusOK)
}

func (s *OIDCWebFlowServer) NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	s.writeStatus(w, fmt.Sprintf("OIDC server doesn't handle the path; url: %v", r.URL), http.StatusNotFound)
}

// waitForReady waits until the server is health.
func (s *OIDCWebFlowServer) waitForReady() error {
	endTime := time.Now().Add(3 * time.Minute)
	for time.Now().Before(endTime) {

		r, err := http.Get(s.Address() + "/healthz")
		if err == nil && r.StatusCode == http.StatusOK {
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return errors.New("timeout waiting for server to be healthy")
}

// Run runs the flow to create a tokensource.
func (s *OIDCWebFlowServer) Run() (oauth2.TokenSource, error) {
	log := s.log

	go func() {
		s.startAndBlock()
	}()
	log.Info("Waiting for OIDC server to be ready")
	if err := s.waitForReady(); err != nil {
		return nil, err
	}
	authURL := s.AuthStartURL()
	log.Info("Opening URL to start Auth Flow", "URL", authURL)
	if err := browser.OpenURL(authURL); err != nil {
		log.Error(err, "Failed to open URL in browser; open it manually", "url", authURL)
		fmt.Printf("Go to the following link in your browser to complete  the OIDC flow: %v\n", authURL)
	}
	// Wait for the token source
	log.Info("Waiting for OIDC login flow to complete")

	defer func() {
		log.Info("Shutting OIDC server down")
		err := s.srv.Shutdown(context.Background())
		if err != nil {
			log.Error(err, "There was a problem shutting the OIDC server down")
		}
	}()
	select {
	case tsOrError := <-s.c:
		if tsOrError.err != nil {
			return nil, errors.Wrapf(tsOrError.err, "OIDC flow didn't complete successfully")
		}
		log.Info("OIDC flow completed")
		return tsOrError.ts, nil
	case <-time.After(3 * time.Minute):
		return nil, errors.New("Timeout waiting for OIDC flow to complete")
	}
}

// startAndBlock starts the server and blocks.
func (s *OIDCWebFlowServer) startAndBlock() {
	log := s.log

	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc(authStartPrefix, s.handleStartWebFlow)
	router.HandleFunc("/healthz", s.HealthCheck)
	router.HandleFunc(authCallbackUrl, s.handleAuthCallback)

	router.NotFoundHandler = http.HandlerFunc(s.NotFoundHandler)

	log.Info("OIDC server is running", "address", s.Address())

	s.srv = &http.Server{Addr: s.host, Handler: router}

	err := s.srv.ListenAndServe()

	if err != nil {
		log.Error(err, "OIDCWebFlowServer returned error")
	}
	log.Info("OIDC server has been shutdown")
}

func (p *Proxy) addRoutes() error {
	router := mux.NewRouter().StrictSlash(true)
	p.router = router

	router.HandleFunc(healthPath, p.healthCheck)

	p.log.Info("Adding OIDC login handlers")
	router.HandleFunc(oauthStart, p.handleOAuthStart)
	u, err := url.Parse(p.handlers.Config().RedirectURL)
	if err != nil {
		return errors.Wrapf(err, "Could not parse URL %v", p.handlers.Config().RedirectURL)
	}
	router.HandleFunc(u.Path, p.handleOAuthCallback)
	router.HandleFunc(idTokenPath, p.oidcEnsureAuth(p.handleToken))

	router.NotFoundHandler = p.oidcEnsureAuth(p.proxyRequest)

	// TODO(jeremy): Can we verify that interceptors for Auth are on each page.
	return nil
}
