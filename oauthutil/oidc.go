package oauthutil

import (
	"context"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/jlewi/p22h/backend/pkg/logging"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// OIDCHandlers provides helpers for server side web apps that want to use OIDC for login.
// It is based on the code in https://github.com/coreos/go-oidc/blob/v3/example/idtoken/app.go.
//
// OIDC is very similar to the OAuth flow.
// see: https://developers.google.com/identity/openid-connect/openid-connect#authenticationuriparameters
//
// These handlers are intended to run on the server it can use the client secret without worrying about the
// client secret being compromised because the client secret isn't distributed to the clients
// as it would in a desktop application or JS application.
//
// OIDCHandlers providers two methods that can be invoked from your webserver to deal with the OAuth web flow.
//
// First, the appropriate handler in your webserver should initiate the login flow by mapping the login URL
// e.g. "/login" to RedirectToAuthURL.
//
//	This handler returns a redirect 302 to the OAuth web server. This handler sets an appropriate state cookie. The value of
//	the state is returned to the caller so that it can be used as a cookie to link data across server invocations.
//	This will set the OAuth2 redirect URI to the redirect URI specified in the config.
//
// Second, your server should have a handler for the redirect URI specified in oauth2.config. That handler
//
//	 should invoke HandleAuthCode. That function will take the Auth code returned by the server and exchange
//		it for an access token. This is then used to obtain an IDToken.
//	 A token source is then returned which will use the JWT as the access code. This can be used to authenticate
//	 to services that use the JWT.
type OIDCHandlers struct {
	log      logr.Logger
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func NewOIDCHandlers(config oauth2.Config, verifier *oidc.IDTokenVerifier) (*OIDCHandlers, error) {
	return &OIDCHandlers{
		log:      zapr.NewLogger(zap.L()),
		config:   config,
		verifier: verifier,
	}, nil
}

func (s *OIDCHandlers) Config() oauth2.Config {
	return s.config
}

// RedirectToAuthURL kicks off the OIDCWebFlow by redirecting to
// the AuthCode URL. It returns the value of the state variable.
// This gets set in a cookie and is also passed through by the OAuth server on redirect.
// The server can use this to track state across the flow.
func (s *OIDCHandlers) RedirectToAuthURL(w http.ResponseWriter, r *http.Request) (string, error) {
	state, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return state, err
	}
	nonce, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return state, err
	}

	// TODO(jeremy): Cookies are not port specific;
	// see https://stackoverflow.com/questions/1612177/are-http-cookies-port-specific#:~:text=Cookies%20do%20not%20provide%20isolation%20by%20port.
	// So if we have two completely instances of the OIDCWebFlowServer running (e.g. in different CLIs) corresponding to two
	// different ports  e.g 127.0.0.1:50002 & 127.0.0.1:60090 the would both be reading/writing the same cookies
	// if the user was somehow going simultaneously going through the flow on both browsers. Extremely unlikely
	// but could still cause concurrency issues. We should address that by adding some random salt to each
	// cookie name at server construction.
	setCallbackCookie(w, r, "state", state)
	setCallbackCookie(w, r, "nonce", nonce)

	redirectURL := s.config.AuthCodeURL(state, oidc.Nonce(nonce))

	s.log.V(logging.Debug).Info("Setting redirect URL", "state", state, "nonce", nonce, "url", redirectURL)
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
func (s *OIDCHandlers) HandleAuthCode(w http.ResponseWriter, r *http.Request) (string, *IDTokenSource, error) {
	ctx := context.Background()

	stateCookie, err := r.Cookie("state")
	if err != nil {
		http.Error(w, "state not found", http.StatusBadRequest)
		return "", nil, err
	}
	actual := r.URL.Query().Get("state")
	state := stateCookie.Value
	if actual != state {
		s.log.Info("state didn't match", "got", actual, "want", state)
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

	// Create an ID token source that wraps this token source
	idTS := &IDTokenSource{
		Source:   ts,
		Verifier: s.verifier,
	}

	// Verify the IDToken
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return state, nil, errors.Errorf("Failed to obtain IDToken")
	}

	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return state, nil, errors.Errorf("Failed to verify IDToken")
	}

	nonce, err := r.Cookie("nonce")
	if err != nil {
		http.Error(w, "nonce not found", http.StatusBadRequest)
		return state, nil, errors.Errorf("Failed to obtain nonce")
	}

	if idToken.Nonce != nonce.Value {
		http.Error(w, "nonce did not match", http.StatusBadRequest)
		return state, nil, errors.Errorf("IDToken's nonce didn't match the nonce cookie")
	}

	return state, idTS, nil
}

// IDTokenSource is a wrapper around a TokenSource that returns the OpenID token as the access token.
type IDTokenSource struct {
	Source   oauth2.TokenSource
	Verifier *oidc.IDTokenVerifier
}

// Token returns an OAuth2 Token which uses the JWT as the bearer token.
// The token is verified using the supplied verifier.
func (s *IDTokenSource) Token() (*oauth2.Token, error) {
	data, err := s.getToken()
	if err != nil {
		return nil, err
	}

	// Create a new OAuthToken in which the Access token is the JWT (i.e. the ID token).
	jwtToken := &oauth2.Token{
		AccessToken: data.idTokJSON,
		Expiry:      data.idTok.Expiry,
	}

	return jwtToken, nil
}

// AccessTokenSource returns a token source for the underlying access token obtained as part of the OIDC flow.
// This can be used with the UserProfile service to get the profile information of the user.
// https://developers.google.com/identity/openid-connect/openid-connect#obtaininguserprofileinformation
func (s *IDTokenSource) AccessTokenSource() oauth2.TokenSource {
	return s.Source
}

// Used to store some intermediary values
type tokenInternals struct {
	tk        *oauth2.Token
	idTokJSON string
	idTok     *oidc.IDToken
}

func (s *IDTokenSource) getToken() (*tokenInternals, error) {
	tk, err := s.Source.Token()
	// TODO(jeremy): The verification steps get repeated on each call to Token even if the token is being reused
	// across calls. We should cache the results of verification so we don't need to redo it on each call.
	if err != nil {
		return nil, errors.Wrapf(err, "IDTokenSource failed to get token from underlying token source")
	}
	// Per https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
	// the ID token is returned in the id_token field
	rawTok, ok := tk.Extra("id_token").(string)
	if !ok {
		return nil, errors.Errorf("Underlying token source didn't have field id_token")
	}

	tok, err := s.Verifier.Verify(context.Background(), rawTok)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to verify ID token")
	}

	return &tokenInternals{
		tk:        tk,
		idTokJSON: rawTok,
		idTok:     tok,
	}, nil
}

// IDToken returns a verified IDToken or an error if a verified token couldn't be obtained
func (s *IDTokenSource) IDToken() (*oidc.IDToken, error) {
	data, err := s.getToken()
	if err != nil {
		return nil, err
	}
	return data.idTok, nil
}

// CommonClaims is a type representing common claims. At least as provided by Google's OIDC
type CommonClaims struct {
	AtHash        string `json:"at_hash"`
	Aud           string `json:"aud"`
	AzP           string `json:"azp"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Exp           int    `json:"exp"`
	FamilyName    string `json:"family_name"`
	GivenName     string `json:"given_name"`
	Locale        string `json:"locale"`
	HD            string `json:"hd"`
	IAT           int    `json:"iat"`
	ISS           string `json:"iss"`
	Name          string `json:"name"`
	Nonce         string `json:"nonce"`
	Picture       string `json:"picture"`
	Sub           string `json:"sub"`
}
