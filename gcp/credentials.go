// Package gcp provides utilities for working with GCP
package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jlewi/monogo/networking"
	"github.com/jlewi/monogo/oauthutil"
	"github.com/jlewi/p22h/backend/api"
	"github.com/jlewi/p22h/backend/pkg/debug"
	"github.com/pkg/browser"

	"github.com/jlewi/monogo/files"

	"cloud.google.com/go/storage"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/jlewi/monogo/gcp/gcs"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	// CredentialDirPermMode unix permission max suitable for directory storing credentials
	CredentialDirPermMode = 0700
	authCallbackUrl       = "/auth/callback"
	authStartPrefix       = "/auth/start"
)

// CredentialHelper defines an interface for getting tokens.
type CredentialHelper interface {
	GetTokenSource(ctx context.Context) (oauth2.TokenSource, error)

	// GetOAuthConfig returns the OAuth2 client configuration
	GetOAuthConfig() *oauth2.Config
}

// WebFlowHelper helps get credentials using the webflow. It is intended for desktop applications.
// It runs a local server to handle the callback from the OAuth server to get the authorization code and return
// a token source.
//
// References: https://developers.google.com/identity/protocols/oauth2/native-app#request-parameter-redirect_uri
// GCP still supports using the loopback device 127.0.0.1 for OAuth credentials for desktop applications.
// It looks like in that case you don't actually have to specify your redirect URI when configuring the OAuth Client
// in the developer console. However, when you specify your OAuth configuration in the code you need to specify the
// redirect URI and it needs to be 127.0.0.1 not localhost.
type WebFlowHelper struct {
	config   *oauth2.Config
	Log      logr.Logger
	host     string
	handlers *oauthutil.OAuthHandlers
	// Server to handle callback
	srv *http.Server
	c   chan tokenSourceOrError
}

// NewWebFlowHelper constructs a new web flow helper. oAuthClientFile should be the path to a credentials.json
// downloaded from the API console.
func NewWebFlowHelper(oAuthClientFile string, scopes []string) (*WebFlowHelper, error) {
	var fHelper files.FileHelper

	if strings.HasPrefix(oAuthClientFile, "gs://") {
		ctx := context.Background()
		client, err := storage.NewClient(ctx)

		if err != nil {
			return nil, err
		}

		fHelper = &gcs.GcsHelper{
			Ctx:    ctx,
			Client: client,
		}
	} else {
		fHelper = &files.LocalFileHelper{}
	}

	reader, err := fHelper.NewReader(oAuthClientFile)

	if err != nil {
		return nil, err

	}
	b, err := io.ReadAll(reader)

	if err != nil {
		return nil, err
	}
	// If modifying these scopes, delete your previously saved token.json.
	config, err := google.ConfigFromJSON(b, scopes...)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to parse client secret file to config")
	}

	port, err := networking.GetFreePort()
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to get free port")
	}
	// Host must match the same as the redirect URI i.e. we can't use localhost in one place and the loopback in
	// another. This because when we open authStartPrefix in the browser it sets a cookie for the domain which will
	// be host. We then read that cookie when we get redirected back to the callback URL. If the cookie is set
	// on localhost then it won't be accessible when we get to 127.0.0.1 and the flow will fail.
	host := fmt.Sprintf("127.0.0.1:%d", port)
	// We need to use 127.0.0.1 because that's what GCP expects for desktop. If we use localhost it won't work.
	// https://developers.google.com/identity/protocols/oauth2/native-app#request-parameter-redirect_uri
	config.RedirectURL = fmt.Sprintf("http://127.0.0.1:%d%v", port, authCallbackUrl)
	handlers, err := oauthutil.NewOAuthHandlers(*config)
	if err != nil {
		return nil, err
	}

	return &WebFlowHelper{
		config:   config,
		Log:      zapr.NewLogger(zap.L()),
		handlers: handlers,
		host:     host,
		c:        make(chan tokenSourceOrError, 10),
	}, nil
}

func (h *WebFlowHelper) GetOAuthConfig() *oauth2.Config {
	return h.config
}

// Run runs the flow to create a tokensource.
// It starts a server in order to provide a callback that the OAuthFlow can redirect to in order to pass the
// authorization code.
// The server is shutdown after the flow is complete. Since the flow should return a refresh token
// it shouldn't be necessary to keep it running.
func (h *WebFlowHelper) Run() (oauth2.TokenSource, error) {
	log := zapr.NewLogger(zap.L())

	go func() {
		h.startAndBlock()
	}()
	log.Info("Waiting for OAuth server to be ready")
	if err := h.waitForReady(); err != nil {
		return nil, err
	}
	authURL := h.AuthStartURL()
	log.Info("Opening URL to start Auth Flow", "URL", authURL)
	if err := browser.OpenURL(authURL); err != nil {
		log.Error(err, "Failed to open URL in browser; open it manually", "url", authURL)
		// TODO(jeremy): How do we scan it it in? Should we fall back to calling GetTokenSource?
		fmt.Printf("Go to the following link in your browser to complete  the OAuth flow: %v\n", authURL)
	}
	// Wait for the token source
	log.Info("Waiting for OAuth flow to complete")

	defer func() {
		log.Info("Shutting OAuth server down")
		err := h.srv.Shutdown(context.Background())
		if err != nil {
			log.Error(err, "There was a problem shutting the OAuth server down")
		}
	}()
	select {
	case tsOrError := <-h.c:
		if tsOrError.err != nil {
			return nil, errors.Wrapf(tsOrError.err, "OAuth flow didn't complete successfully")
		}
		log.Info("OAUth flow completed")
		return tsOrError.ts, nil
	case <-time.After(3 * time.Minute):
		return nil, errors.New("Timeout waiting for OIDC flow to complete")
	}
}

// startAndBlock starts the server and blocks.
func (h *WebFlowHelper) startAndBlock() {
	log := zapr.NewLogger(zap.L())

	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc(authStartPrefix, h.handleStartWebFlow)
	router.HandleFunc("/healthz", h.HealthCheck)
	router.HandleFunc(authCallbackUrl, h.handleAuthCallback)

	router.NotFoundHandler = http.HandlerFunc(h.NotFoundHandler)

	log.Info("OAuth server is running", "address", h.Address())

	h.srv = &http.Server{Addr: h.host, Handler: router}

	err := h.srv.ListenAndServe()

	// ListenAndServe will return ErrServerClosed when the server is shutdown.
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error(err, "OAuth server returned error")
	}
	log.Info("OAuth server has been shutdown")
}

// waitForReady waits until the server is health.
func (h *WebFlowHelper) waitForReady() error {
	endTime := time.Now().Add(3 * time.Minute)
	for time.Now().Before(endTime) {

		r, err := http.Get(h.Address() + "/healthz")
		if err == nil && r.StatusCode == http.StatusOK {
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return errors.New("timeout waiting for server to be healthy")
}

// handleStartWebFlow kicks off the OAuthWebFlow.
// It was copied from: https://github.com/coreos/go-oidc/blob/2cafe189143f4a454e8b4087ef892be64b1c77df/example/idtoken/app.go#L65
// It sets some cookies before redirecting to the OAuth provider's URL for obtaining an authorization code.
func (h *WebFlowHelper) handleStartWebFlow(w http.ResponseWriter, r *http.Request) {
	log := zapr.NewLogger(zap.L())
	// N.B. we currently ignore the cookie and state because we run thisflow in a CLI/application. The implicit
	// assumption is that a single user is going through the flow a single time so we don't need to use
	// cookie and state to keep track of the user's session. We also don't need to use the cookie
	// to keep track of the page the user was visiting before they started the flow.
	_, err := h.handlers.RedirectToAuthURL(w, r)
	if err != nil {
		log.Error(err, "Failed to handle auth start")
	}
}

func (h *WebFlowHelper) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	log := zapr.NewLogger(zap.L())
	_, ts, err := h.handlers.HandleAuthCode(w, r)
	if err != nil {
		log.Error(err, "Failed to handle auth callback")
		h.c <- tokenSourceOrError{err: err}
		return
	}

	h.c <- tokenSourceOrError{ts: ts}
	if _, err := w.Write([]byte("OAuth flow completed; you can close this window and return to your application")); err != nil {
		log.Error(err, "Failed to write response")
	}
}

// GetTokenSource requests a token from the web, then returns the retrieved token.
// TODO(jeremy): Deprecate this method in favor of Run.
func (h *WebFlowHelper) GetTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	return h.Run()
}

// AuthStartURL returns the URL to kickoff the oauth login flow.
func (s *WebFlowHelper) AuthStartURL() string {
	return s.Address() + authStartPrefix
}

func (h *WebFlowHelper) Address() string {
	return fmt.Sprintf("http://%v", h.host)
}

func (h *WebFlowHelper) writeStatus(w http.ResponseWriter, message string, code int) {
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

func (h *WebFlowHelper) HealthCheck(w http.ResponseWriter, r *http.Request) {
	h.writeStatus(w, "OAuth server is running", http.StatusOK)
}

func (h *WebFlowHelper) NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	h.writeStatus(w, fmt.Sprintf("OAuth server doesn't handle the path; url: %v", r.URL), http.StatusNotFound)
}

// TokenCache defines an interface for caching tokens
type TokenCache interface {
	GetToken() (*oauth2.Token, error)
	Save(token *oauth2.Token) error
}

// FileTokenCache implements caching to a file.
type FileTokenCache struct {
	CacheFile string
	Log       logr.Logger
}

func (c *FileTokenCache) GetToken() (*oauth2.Token, error) {
	f, err := os.Open(c.CacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Save saves a token to a file path.
func (c *FileTokenCache) Save(token *oauth2.Token) error {
	c.Log.Info("Saving credential", "file", c.CacheFile)

	dir := filepath.Dir(c.CacheFile)

	_, err := os.Stat(dir)

	if err != nil {
		if os.IsNotExist(err) {
			c.Log.Info("Create cache directory", "dir", dir)
			err := os.MkdirAll(dir, CredentialDirPermMode)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	f, err := os.OpenFile(c.CacheFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		c.Log.Error(err, "Unable to cache oauth token: %v")
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(token)
}

// CachedCredentialHelper is a credential helper that will cache the credential.
type CachedCredentialHelper struct {
	CredentialHelper CredentialHelper
	TokenCache       TokenCache
	Log              logr.Logger
}

func (h *CachedCredentialHelper) GetOAuthConfig() *oauth2.Config {
	return h.CredentialHelper.GetOAuthConfig()
}

func (c *CachedCredentialHelper) GetTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	log := c.Log
	// Try the cache.
	tok, err := c.TokenCache.GetToken()

	if err != nil {
		return nil, err
	}

	if tok == nil {
		// Cache is empty so get a token
		ts, err := c.CredentialHelper.GetTokenSource(context.Background())

		if err != nil {
			return nil, err
		}

		// Save the token
		newTok, err := ts.Token()
		tok = newTok
		if err != nil {
			log.Error(err, "Could generate token from token source")
			return ts, err
		}
		err = c.TokenCache.Save(newTok)

		if err != nil {
			log.Error(err, "Could not save token")
		}
	}

	ts := c.CredentialHelper.GetOAuthConfig().TokenSource(ctx, tok)
	return ts, nil
}

type tokenSourceOrError struct {
	ts  oauth2.TokenSource
	err error
}
