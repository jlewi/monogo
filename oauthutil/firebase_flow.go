package oauthutil

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/zapr"
	"github.com/gorilla/mux"
	"github.com/jlewi/p22h/backend/api"
	"github.com/jlewi/p22h/backend/pkg/debug"
	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

// embed the assets
//
//go:embed assets
var assetFiles embed.FS

// FirebaseFlowServer creates a server to be used to go through firebase login.
type FirebaseFlowServer struct {
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
	host     string
	c        chan tokenSourceOrError
	srv      *http.Server
	handlers *OIDCHandlers
}

//func NewFirebaseFlowServer(config oauth2.Config, verifier *oidc.IDTokenVerifier, log logr.Logger) (*FirebaseFlowServer, error) {
//	u, err := url.Parse(config.RedirectURL)
//	if err != nil {
//		return nil, errors.Wrapf(err, "Could not parse URL %v", config.RedirectURL)
//	}
//
//	handlers, err := NewOIDCHandlers(config, verifier)
//	if err != nil {
//		return nil, err
//	}
//
//	return &FirebaseFlowServer{
//		log:      log,
//		config:   config,
//		verifier: verifier,
//		host:     u.Host,
//		c:        make(chan tokenSourceOrError, 10),
//		handlers: handlers,
//	}, nil
//}

func NewFirebaseFlowServer() (*FirebaseFlowServer, error) {
	return &FirebaseFlowServer{
		host: "localhost:9010",
		c:    make(chan tokenSourceOrError, 10),
	}, nil
}
func (s *FirebaseFlowServer) Address() string {
	return fmt.Sprintf("http://%v", s.host)
}

// AuthStartURL returns the URL to kickoff the oauth login flow.
func (s *FirebaseFlowServer) AuthStartURL() string {
	return s.Address() + "login.html"
}

func (s *FirebaseFlowServer) writeStatus(w http.ResponseWriter, message string, code int) {
	log := zapr.NewLogger(zap.L())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	resp := api.RequestStatus{
		Kind:    "RequestStatus",
		Message: message,
		Code:    code,
	}

	enc := json.NewEncoder(w)
	if err := enc.Encode(resp); err != nil {
		log.Error(err, "Failed to marshal RequestStatus", "RequestStatus", resp, "code", code)
	}

	if code != http.StatusOK {
		caller := debug.ThisCaller()
		log.Info("HTTP error", "RequestStatus", resp, "code", code, "caller", caller)
	}
}

func (s *FirebaseFlowServer) HealthCheck(w http.ResponseWriter, r *http.Request) {
	s.writeStatus(w, "FirebaseFlow server is running", http.StatusOK)
}

func (s *FirebaseFlowServer) NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	s.writeStatus(w, fmt.Sprintf("FirebaseFlow server doesn't handle the path; url: %v", r.URL), http.StatusNotFound)
}

// waitForReady waits until the server is healthy.
func (s *FirebaseFlowServer) waitForReady() error {
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
func (s *FirebaseFlowServer) Run() (*IDTokenSource, error) {
	log := zapr.NewLogger(zap.L())

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
		// TODO(jeremy): This is a hack to deal with a race condition in which the server starts shutting down
		// but oauth flow still sends it some request.
		return tsOrError.ts, nil
	case <-time.After(3 * time.Minute):
		return nil, errors.New("Timeout waiting for OIDC flow to complete")
	}

}

// startAndBlock starts the server and blocks.
func (s *FirebaseFlowServer) startAndBlock() {
	log := zapr.NewLogger(zap.L())

	router := mux.NewRouter().StrictSlash(true)

	// http.FS can be used to create a http Filesystem
	var staticFS = http.FS(assetFiles)
	//fs := http.FileServer(staticFS)

	assets, err := assetFiles.ReadDir("assets")
	if err != nil {
		panic(err)
	}

	// Add the assets individually because we don't want to serve them behind a prefix because then
	// we'd have to update all the links in the asset directory
	for _, f := range assets {
		log.Info("Adding asset", "asset", f.Name())
		router.HandleFunc("/"+f.Name(), func(w http.ResponseWriter, r *http.Request) {
			b, err := staticFS.Open("assets/" + f.Name())
			if err != nil {
				s.writeStatus(w, fmt.Sprintf("Failed to open asset %v", f.Name()), http.StatusInternalServerError)
				return
			}
			http.ServeContent(w, r, f.Name(), time.Time{}, b)
		})
	}
	//router.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", fs))
	//router.HandleFunc(authStartPrefix, s.handleStartWebFlow)
	router.HandleFunc("/healthz", s.HealthCheck)
	//router.HandleFunc(authCallbackUrl, s.handleAuthCallback)

	router.NotFoundHandler = http.HandlerFunc(s.NotFoundHandler)

	log.Info("FireBase flow server is running", "address", s.Address())

	s.srv = &http.Server{Addr: s.host, Handler: router}

	if err := s.srv.ListenAndServe(); err != nil {
		log.Error(err, "FirebaseFlowServer returned error")
	}
	log.Info("FirebaseFlowServer server has been shutdown")
}

//// handleStartWebFlow kicks off the OIDC web flow.
//// It was copied from: https://github.com/coreos/go-oidc/blob/2cafe189143f4a454e8b4087ef892be64b1c77df/example/idtoken/app.go#L65
//// It sets some cookies before redirecting to the OIDC provider's URL for obtaining an authorization code.
//func (s *FirebaseFlowServer) handleStartWebFlow(w http.ResponseWriter, r *http.Request) {
//	// N.B. we currently ignore the cookie and state because we run thisflow in a CLI/application. The implicit
//	// assumption is that a single user is going through the flow a single time so we don't need to use
//	// cookie and state to keep track of the user's session. We also don't need to use the cookie
//	// to keep track of the page the user was visiting before they started the flow.
//	_, err := s.handlers.RedirectToAuthURL(w, r)
//	if err != nil {
//		s.log.Error(err, "Failed to handle auth start")
//	}
//}
//
//// handleAuthCallback handles the OIDC auth callback code copied from
//// https://github.com/coreos/go-oidc/blob/2cafe189143f4a454e8b4087ef892be64b1c77df/example/idtoken/app.go#L82.
////
//// The Auth callback is invoked in step 21 of the OIDC protocol.
//// https://solid.github.io/solid-oidc/primer/#:~:text=Solid%2DOIDC%20builds%20on%20top,authentication%20in%20the%20Solid%20ecosystem.
//// The OpenID server responds with a 303 redirect to the AuthCallback URL and passes the authorization code.
//// This is a mechanism for the authorization code to be passed into the code.
//func (s *FirebaseFlowServer) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
//	_, ts, err := s.handlers.HandleAuthCode(w, r)
//	if err != nil {
//		s.log.Error(err, "Failed to handle auth callback")
//		s.c <- tokenSourceOrError{err: err}
//		return
//	}
//
//	s.c <- tokenSourceOrError{ts: ts}
//}
