package oauthutil

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/gorilla/mux"
	"github.com/jlewi/monogo/networking"
	"github.com/jlewi/p22h/backend/api"
	"github.com/jlewi/p22h/backend/pkg/debug"
	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"
)

const (
	authStartPrefix = "/auth/start"
	authCallbackUrl = "/auth/callback"
)

// OIDCWebFlowServer creates a server to be used to go through the web flow to get a token source
// for use in a CLI.
//
// It is based on the code in https://github.com/coreos/go-oidc/blob/v3/example/idtoken/app.go.
//
// N.B: https://github.com/coreos/go-oidc/issues/354 is discussing creating a reusable server.
//
// Your OAuth2 credential should have http://127.0.0.1/auth/callback as an allowed redirect URL.
// TODO(jeremy): Add caching of the refresh token.
type OIDCWebFlowServer struct {
	log      logr.Logger
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
	host     string
	c        chan tokenSourceOrError
	srv      *http.Server
	handlers *OIDCHandlers
}

func NewOIDCWebFlowServer(config oauth2.Config, verifier *oidc.IDTokenVerifier, log logr.Logger) (*OIDCWebFlowServer, error) {
	u, err := url.Parse(config.RedirectURL)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not parse URL %v", config.RedirectURL)
	}

	handlers, err := NewOIDCHandlers(config, verifier)
	if err != nil {
		return nil, err
	}

	return &OIDCWebFlowServer{
		log:      log,
		config:   config,
		verifier: verifier,
		host:     u.Host,
		c:        make(chan tokenSourceOrError, 10),
		handlers: handlers,
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
// The server is shutdown after the flow is complete. Since the flow should return a refresh token
// it shouldn't be necessary to keep it running.
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

// handleStartWebFlow kicks off the OIDC web flow.
// It was copied from: https://github.com/coreos/go-oidc/blob/2cafe189143f4a454e8b4087ef892be64b1c77df/example/idtoken/app.go#L65
// It sets some cookies before redirecting to the OIDC provider's URL for obtaining an authorization code.
func (s *OIDCWebFlowServer) handleStartWebFlow(w http.ResponseWriter, r *http.Request) {
	// N.B. we currently ignore the cookie and state because we run thisflow in a CLI/application. The implicit
	// assumption is that a single user is going through the flow a single time so we don't need to use
	// cookie and state to keep track of the user's session. We also don't need to use the cookie
	// to keep track of the page the user was visiting before they started the flow.
	_, err := s.handlers.RedirectToAuthURL(w, r)
	if err != nil {
		s.log.Error(err, "Failed to handle auth start")
	}
}

// handleAuthCallback handles the OIDC auth callback code copied from
// https://github.com/coreos/go-oidc/blob/2cafe189143f4a454e8b4087ef892be64b1c77df/example/idtoken/app.go#L82.
//
// The Auth callback is invoked in step 21 of the OIDC protocol.
// https://solid.github.io/solid-oidc/primer/#:~:text=Solid%2DOIDC%20builds%20on%20top,authentication%20in%20the%20Solid%20ecosystem.
// The OpenID server responds with a 303 redirect to the AuthCallback URL and passes the authorization code.
// This is a mechanism for the authorization code to be passed into the code.
func (s *OIDCWebFlowServer) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	_, ts, err := s.handlers.HandleAuthCode(w, r)
	if err != nil {
		s.log.Error(err, "Failed to handle auth callback")
		s.c <- tokenSourceOrError{err: err}
		return
	}

	s.c <- tokenSourceOrError{ts: ts}
}

type tokenSourceOrError struct {
	ts  oauth2.TokenSource
	err error
}

// OIDCWebFlowFlags creates the OIDCWebFlowServer from command line flags.
type OIDCWebFlowFlags struct {
	Issuer          string
	OAuthClientFile string
}

func (f *OIDCWebFlowFlags) AddFlags(cmd *cobra.Command) {
	dirname, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("failed to get home directory. This only affects default values for command line flags. Error; %v", err)
		dirname = "/"
	}
	// TODO(jeremy): What's a more sensible default?
	defaultOAuthClientFile := path.Join(dirname, "secrets", "roboweb-lewi-iap-oauth-client.json ")
	cmd.Flags().StringVarP(&f.Issuer, "oidc-issuer", "", "https://accounts.google.com", "The OIDC issuer to use when using OIDC")
	cmd.Flags().StringVarP(&f.OAuthClientFile, "oidc-client-file", "", defaultOAuthClientFile, "The file containing the OAuth client to use with OIDC")
}

func (f *OIDCWebFlowFlags) Flow() (*OIDCWebFlowServer, error) {
	log := zapr.NewLogger(zap.L())

	b, err := os.ReadFile(f.OAuthClientFile)

	if err != nil {
		return nil, err
	}

	// If modifying these scopes, delete your previously saved token.json.
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	// "openid" is a required scope for OpenID Connect flows.
	config, err := google.ConfigFromJSON(b, scopes...)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to parse client secret file to config")
	}

	// TODO(jeremy): make this a parameter. 0 picks a free port.
	port, err := networking.GetFreePort()
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to get free port")
	}
	// We need to rewrite the RedirectURL in the config because the webflowserver gets the value
	// from the callback URL
	config.RedirectURL = fmt.Sprintf("http://127.0.0.1:%v%v", port, authCallbackUrl)

	p, err := oidc.NewProvider(context.Background(), f.Issuer)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create OIDC provider for %v", f.Issuer)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	config.Endpoint = p.Endpoint()

	oidcConfig := &oidc.Config{
		ClientID: config.ClientID,
	}
	verifier := p.Verifier(oidcConfig)

	return NewOIDCWebFlowServer(*config, verifier, log)
}
