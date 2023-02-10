package oauthutil

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/gorilla/mux"
	"github.com/jlewi/monogo/helpers"
	"github.com/jlewi/monogo/iap"
	"github.com/jlewi/p22h/backend/api"
	"github.com/jlewi/p22h/backend/pkg/debug"
	"github.com/jlewi/p22h/backend/pkg/logging"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	sessionCookie = "oidc-proxy-sid"
	oauthStart    = "/oidc/start"
	idTokenPath   = "/oidc/token"
	healthPath    = "/healthz"
)

// Proxy is an OIDC proxy. It mimics IAP when running a server locally.
// It will programmatically obtain an OIDC token from Google and then set the appropriate header before
// forwarding the request to the target
type Proxy struct {
	log        logr.Logger
	base       string
	port       int
	sessions   map[string]*session
	stateToSid map[string]string
	router     *mux.Router
	srv        *http.Server
	// handlers is the OIDC handlers. This should only be used when not running behind an identity proxy.
	handlers *OIDCHandlers

	mu sync.Mutex
}

// session keeps track of all the data to proxy requests.
type session struct {
	// Ts is the IDTokenSource for this user
	// TODO(jeremy): How can we provide better security to prevent accessing the wrong users Ts. i.e. how
	// can we find a way to encrypt it using EUC that are only available from the user request?
	Ts *IDTokenSource
	// NextURL is the path to redirect the user to after they login
	NextURL string
}

// NewProxy creates a new server running on localhost.
func NewProxy(h *OIDCHandlers, port int) (*Proxy, error) {
	// TODO(jeremy): Should we compare this to the redirectURL to make sure it is in sync
	base := fmt.Sprintf("http://localhost:%v", port)

	p := &Proxy{
		log:        zapr.NewLogger(zap.L()),
		base:       base,
		port:       port,
		handlers:   h,
		sessions:   make(map[string]*session),
		stateToSid: make(map[string]string),
	}
	p.log.Info("base href set", "baseHREF", base)
	p.log.Info("OAuth client", "redirectURL", h.Config().RedirectURL)

	if err := p.addRoutes(); err != nil {
		return nil, err
	}
	return p, nil
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

// StartAndBlock starts the server and blocks.
func (p *Proxy) StartAndBlock() {
	log := p.log
	log.Info("Binding all network interfaces", "port", p.port)
	p.srv = &http.Server{Addr: fmt.Sprintf(":%v", p.port), Handler: p.router}

	p.trapInterrupt()
	err := p.srv.ListenAndServe()

	if err != nil {
		if err == http.ErrServerClosed {
			log.Info("OIDC Proxy has been shutdown")
		} else {
			log.Error(err, "Server aborted with error")
		}
	}
}

// trapInterrupt waits for a shutdown signal and shutsdown the server
func (p *Proxy) trapInterrupt() {
	sigs := make(chan os.Signal, 10)
	// SIGSTOP and SIGTERM can't be caught; however SIGINT works as expected when using ctl-z
	// to interrupt the process
	signal.Notify(sigs, syscall.SIGINT)

	go func() {
		msg := <-sigs
		p.log.Info("Recieved shutdown signal", "sig", msg)
		if err := p.srv.Shutdown(context.Background()); err != nil {
			p.log.Error(err, "Error shutting down server.")
		}
	}()
}

func (p *Proxy) healthCheck(w http.ResponseWriter, r *http.Request) {
	p.log.V(logging.Debug).Info("Call to /healthz")
	p.writeStatus(w, "Starling server is running", http.StatusOK)
}

// proxyRequest is a function to be used as the director to modify a request in ReverseProxy
func (p *Proxy) proxyRequest(w http.ResponseWriter, r *http.Request) {
	log := p.log
	sid := p.getSID(w, r)
	if sid == "" {
		return
	}

	sess, ok := p.getSession(sid)
	if !ok {
		p.writeStatus(w, "Failed to find session", http.StatusInternalServerError)
		return
	}

	if sess.Ts == nil {
		log.Info("Profile request failed; no token source")
		http.Error(w, "no token source for state", http.StatusBadRequest)
		return
	}
	tok, err := sess.Ts.Token()
	if err != nil {
		p.writeStatus(w, fmt.Sprintf("Failed to get IDToken; error %v", err), http.StatusInternalServerError)
		return
	}
	// TODO(jeremy): Make this a parameter
	target := &url.URL{
		Scheme: "http",
		Host:   "localhost:8080",
	}
	targetQuery := target.RawQuery
	// The AccessToken should be the JWT
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path, req.URL.RawPath = joinURLPath(target, req.URL)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}

		req.Header.Set(iap.JWTHeader, tok.AccessToken)
		// Also set the authorization header because sometimes we aren't using IAP
		// and that's what we use.
		req.Header.Set("Authorization", tok.AccessToken)
	}
	h := &httputil.ReverseProxy{Director: director}
	h.ServeHTTP(w, r)
}

func (p *Proxy) writeStatus(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	resp := api.RequestStatus{
		Kind:    "RequestStatus",
		Message: message,
		Code:    code,
	}

	enc := json.NewEncoder(w)
	if err := enc.Encode(resp); err != nil {
		p.log.Error(err, "Failed to marshal RequestStatus", "RequestStatus", resp, "code", code)
	}

	if code != http.StatusOK {
		caller := debug.ThisCaller()
		p.log.Info("HTTP error", "RequestStatus", resp, "code", code, "caller", caller)
	}
}

// handleToken displays the information in the IDToken. Useful for debugging
func (p *Proxy) handleToken(w http.ResponseWriter, r *http.Request) {
	log := p.log
	sid := p.getSID(w, r)
	if sid == "" {
		return
	}

	sess, ok := p.getSession(sid)
	if !ok {
		p.writeStatus(w, "Failed to find session", http.StatusInternalServerError)
		return
	}

	idTok, err := sess.Ts.IDToken()
	if err != nil {
		log.Error(err, "Profile request failed; could not get ID token")
		http.Error(w, fmt.Sprintf("Profile request failed; could not get ID token: %v", err), http.StatusInternalServerError)
		return
	}

	_, err = w.Write([]byte(helpers.PrettyString(idTok)))
	helpers.IgnoreError(err)

	_, err = w.Write([]byte("\n"))
	helpers.IgnoreError(err)
	claims := map[string]interface{}{}

	if err := idTok.Claims(&claims); err != nil {
		log.Error(err, "Failed to get claims from ID token")
		_, err = w.Write([]byte("Failed to get claims from ID token"))
		helpers.IgnoreError(err)
		return
	}
	_, err = w.Write([]byte(helpers.PrettyString(claims)))
	helpers.IgnoreError(err)
}

// getSID returns the cookie or empty string if there is none.
// Caller should check if the cookie is empty and if is just return because we shouldn't proceed.
// This shouldn't happen because the interceptor should have ensured there is a cookie
func (p *Proxy) getSID(w http.ResponseWriter, r *http.Request) string {
	log := p.log
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		err := errors.Errorf("Missing session cookie")
		log.Error(err, "Missing session cookie")
		p.writeStatus(w, err.Error(), http.StatusBadRequest)
		return ""
	}
	return cookie.Value

}

func (p *Proxy) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	cookie := p.getSID(w, r)
	if cookie == "" {
		return
	}
	log := p.log
	// Kick off the handle flow.
	state, err := p.handlers.RedirectToAuthURL(w, r)
	if err != nil {
		log.Error(err, "Failed to start OAuth flow")
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.stateToSid[state] = cookie
}

func (p *Proxy) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	log := p.log
	// Kick off the handle flow.
	state, ts, err := p.handlers.HandleAuthCode(w, r)
	if err != nil {
		log.Error(err, "Failed to handle OAuthCallback")
		return
	}

	cookie := func() string {
		p.mu.Lock()
		defer p.mu.Unlock()

		cookie, ok := p.stateToSid[state]
		if !ok {
			return ""
		}
		return cookie
	}()

	session, ok := p.getSession(cookie)
	if !ok {
		p.writeStatus(w, "Failed to find session", http.StatusInternalServerError)
	}
	session.Ts = ts
	p.setSession(cookie, session)
	nextURL := session.NextURL
	if nextURL == "" {
		nextURL = p.pathToURL(idTokenPath)
	}
	// Redirect to the profile do this after persisting the token source because the handler will try to access
	// it and we want to avoid race conditions
	log.Info("OAuth completed; redirecting", "url", p.pathToURL(nextURL))
	http.Redirect(w, r, nextURL, http.StatusFound)
}

// getSession is thread safe. It returns a copy of the session so changes are not persisted
func (p *Proxy) getSession(cookie string) (session, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	sess, ok := p.sessions[cookie]
	if !ok {
		return session{}, false
	}
	return *sess, ok
}

// setSession sets the Session. It will override the current value
func (p *Proxy) setSession(cookie string, sess session) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if cookie == "" {
		p.log.Error(errors.New("Tried to set session for empty cookie"), "Error setting cookie")
		return
	}

	p.sessions[cookie] = &sess
}

// pathToURL returns the full URL path for the given URL.
func (p *Proxy) pathToURL(path string) string {
	return fmt.Sprintf("%v%v", p.base, path)
}

// oidcEnsureAuth is the interceptor used when relying on OIDC and not IAP
// this should only be used when running locally.
func (p *Proxy) oidcEnsureAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := p.log
		cookie, err := r.Cookie(sessionCookie)
		var sess *session
		if err == nil {
			if currentSes, ok := p.getSession(cookie.Value); ok {
				sess = &currentSes
			} else {
				log.Info("No session stored for cookie; creating new session")
				sess = nil
			}
		}

		if sess == nil {
			log.V(logging.Debug).Info("No SessionCookie redirecting to login")
			sid, err := helpers.RandString(24)
			if err != nil {
				log.Error(err, "Failed to generate session cookie")
				p.writeStatus(w, "Failed to generate session", http.StatusInternalServerError)
				return
			}

			p.setSession(sid, session{
				// This should hopefully include query arguments.
				NextURL: r.URL.String(),
			})
			log.V(logging.Debug).Info("Setting session cookie")
			setCookie(w, r, sessionCookie, sid)
			http.Redirect(w, r, p.pathToURL(oauthStart), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// copied from: https://github.com/coreos/go-oidc/blob/2cafe189143f4a454e8b4087ef892be64b1c77df/example/idtoken/app.go#L34
func setCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
		// See: https://medium.com/swlh/7-keys-to-the-mystery-of-a-missing-cookie-fdf22b012f09
		// Match all paths
		Path: "/",
	}
	http.SetCookie(w, c)
}

// copied from reverseproxy.go (httputil)
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// copied from reverseproxy.go (httputil)
func joinURLPath(a, b *url.URL) (path, rawpath string) {
	if a.RawPath == "" && b.RawPath == "" {
		return singleJoiningSlash(a.Path, b.Path), ""
	}
	// Same as singleJoiningSlash, but uses EscapedPath to determine
	// whether a slash should be added
	apath := a.EscapedPath()
	bpath := b.EscapedPath()

	aslash := strings.HasSuffix(apath, "/")
	bslash := strings.HasPrefix(bpath, "/")

	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], apath + bpath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, apath + "/" + bpath
	}
	return a.Path + b.Path, apath + bpath
}
