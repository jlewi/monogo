package oauthutil

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"

	"github.com/go-logr/logr"
	"github.com/jlewi/p22h/backend/pkg/logging"
	"golang.org/x/oauth2"
)

// OAuthHandlers provides helpers for server side web apps.
// see: https://developers.google.com/identity/protocols/oauth2/web-server
//
// See also the flow diagram
//
//		https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow
//	 https://developers.google.com/identity/protocols/oauth2#webserver
//
// Since it runs on the server it can use the client secret without worrying about the client secret
// being compromised because the client secret isn't distributed to the clients
// as it would in a desktop application or JS application.
//
// OAuthHandlers providers two methods that can be invoked from your webserver to deal with the OAuth web flow.
//
// First, the appropriate handler in your webserver should call to RedirectToAuthURL. This will
//
//	return a redirect 302 to the OAuth web server. This handler sets an appropriate state cookie. The value of
//	the state is returned to the caller so that it can be used as a cookie to link data across server invocations.
//	This will set the OAuth2 redirect URI to the redirect URI specified in the config.
//
// Second, your server should have a handler for the redirect URI specified in oauth2.config. That handler
//
//	should invoke HandleAuthCode. That function will take the Auth code returned by the server and exchange
//	it for an access token. The access token is returned as an oauth2.TokenSource which the caller can then use
//	in subsequent calls. In addition it returns the value of the state cookie. This allows the server to know
//	which client issued the call and should be associated with the token source.
type OAuthHandlers struct {
	log    logr.Logger
	config oauth2.Config
}

func NewOAuthHandlers(config oauth2.Config) (*OAuthHandlers, error) {
	return &OAuthHandlers{
		log:    zapr.NewLogger(zap.L()),
		config: config,
	}, nil
}

// RedirectToAuthURL kicks off the OAuthWebFlow by redirecting to
// the AuthCode URL. It returns the value of the state variable.
// This gets set in a cookie and is also passed through by the OAuth server on redirect.
// The server can use this to track state across the flow.
func (s *OAuthHandlers) RedirectToAuthURL(w http.ResponseWriter, r *http.Request) (string, error) {
	state, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return state, err
	}

	// N.B: Cookies are not port specific;
	// see https://stackoverflow.com/questions/1612177/are-http-cookies-port-specific#:~:text=Cookies%20do%20not%20provide%20isolation%20by%20port.
	// So if we have two completely instances of the OAuthHandlers running (e.g. in different CLIs) corresponding to two
	// different ports  e.g 127.0.0.1:50002 & 127.0.0.1:60090 the would both be reading/writing the same cookies
	// if the user was somehow going simultaneously going through the flow on both browsers. Extremely unlikely
	// but could still cause concurrency issues. We should address that by adding some random salt to each
	// cookie name at server construction.
	setCallbackCookie(w, r, "state", state)

	redirectURL := s.config.AuthCodeURL(state)

	s.log.V(logging.Debug).Info("Setting redirect URL", "state", state, "url", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return state, nil
}

// HandleAuthCode handles the Auth Code returned by the Authorization server.
// It exchanges the auth code for an access token (and refresh token if access type is offline) and creates a
// TokenSource.
//
// This should be invoked in step 5 of the Auth flow as described in
// https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow)
// and takes care of steps 6 & 7.
//
// It returns the tokensource along with the state value.
// The caller can use the tokensource to make calls to authorized APIs.
func (s *OAuthHandlers) HandleAuthCode(w http.ResponseWriter, r *http.Request) (string, oauth2.TokenSource, error) {
	ctx := context.Background()

	state, err := r.Cookie("state")
	if err != nil {
		http.Error(w, "state not found", http.StatusBadRequest)
		return "", nil, err
	}
	actual := r.URL.Query().Get("state")
	if actual != state.Value {
		s.log.Info("state didn't match", "got", actual, "want", state.Value)
		http.Error(w, "state did not match", http.StatusBadRequest)
		return "", nil, err
	}

	oauth2Token, err := s.config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return "", nil, err
	}

	// Create a tokensource. This will take care of automatically refreshing the token if necessary
	ts := s.config.TokenSource(ctx, oauth2Token)
	return state.Value, ts, nil
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// copied from: https://github.com/coreos/go-oidc/blob/2cafe189143f4a454e8b4087ef892be64b1c77df/example/idtoken/app.go#L34
func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
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
