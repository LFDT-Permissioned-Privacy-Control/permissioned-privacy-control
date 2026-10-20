package auth

import (
	"context"
	"errors"
	"fmt"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// AzureADAuthenticator performs Azure AD / Microsoft Entra ID OIDC authentication.
type AzureADAuthenticator struct {
	clientID     string
	clientSecret string
	tenantID     string
	// spAudience is the expected `aud` for service-principal (client-credentials)
	// access tokens validated by VerifyAccessToken (RD-1120). When empty it
	// defaults to clientID. It typically differs from clientID because the
	// client requests the token for our API resource (e.g. api://<app-id>).
	spAudience string
	provider   *gooidc.Provider
}

// AzureIdentity holds the verified identity extracted from an Azure AD id_token.
type AzureIdentity struct {
	OID               string // Object ID — stable, immutable identifier
	TenantID          string // Tenant ID — identifies the Azure AD tenant
	Email             string
	Name              string
	PreferredUsername string
}

// NewAzureADAuthenticator creates an authenticator by fetching the OIDC discovery document.
// Uses "common" as tenantID for multi-tenant / personal Microsoft accounts.
func NewAzureADAuthenticator(clientID, clientSecret, tenantID string) (*AzureADAuthenticator, error) {
	issuerURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)

	// Multi-tenant endpoints ("common", "organizations") return tokens whose issuer
	// contains the actual tenant ID, which differs from "common". Skip issuer check.
	ctx := context.Background()
	if tenantID == "common" || tenantID == "organizations" {
		ctx = gooidc.InsecureIssuerURLContext(ctx, issuerURL)
	}

	provider, err := gooidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover Azure AD OIDC configuration: %w", err)
	}

	return &AzureADAuthenticator{
		clientID:     clientID,
		clientSecret: clientSecret,
		tenantID:     tenantID,
		provider:     provider,
	}, nil
}

// GetAuthorizationURL returns the Microsoft login URL to redirect the user to.
// state is the CSRF token; nonce prevents id_token replay attacks.
func (a *AzureADAuthenticator) GetAuthorizationURL(redirectURI, state, nonce string) string {
	return a.oauthConfig(redirectURI).AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce))
}

// ExchangeCode exchanges an authorization code for a verified AzureIdentity.
// Validates id_token signature, expiry, audience, and nonce.
func (a *AzureADAuthenticator) ExchangeCode(ctx context.Context, code, redirectURI, nonce string) (*AzureIdentity, error) {
	token, err := a.oauthConfig(redirectURI).Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("id_token missing from token response")
	}

	skipIssuer := a.tenantID == "common" || a.tenantID == "organizations"
	verifier := a.provider.Verifier(&gooidc.Config{
		ClientID:        a.clientID,
		SkipIssuerCheck: skipIssuer,
	})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token verification failed: %w", err)
	}

	// Verify nonce to prevent replay attacks
	if idToken.Nonce != nonce {
		return nil, errors.New("nonce mismatch in id_token")
	}

	var claims struct {
		OID               string `json:"oid"`
		TenantID          string `json:"tid"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract id_token claims: %w", err)
	}
	if claims.OID == "" {
		return nil, errors.New("oid claim missing from id_token")
	}
	if claims.TenantID == "" {
		return nil, errors.New("tid claim missing from id_token")
	}

	return &AzureIdentity{
		OID:               claims.OID,
		TenantID:          claims.TenantID,
		Email:             claims.Email,
		Name:              claims.Name,
		PreferredUsername: claims.PreferredUsername,
	}, nil
}

// SetServicePrincipalAudience sets the expected audience for service-principal
// access tokens validated by VerifyAccessToken (RD-1120). An empty value leaves
// the default (clientID). Wired once at startup from AZURE_AD_SP_AUDIENCE.
func (a *AzureADAuthenticator) SetServicePrincipalAudience(audience string) {
	a.spAudience = audience
}

// VerifyAccessToken validates an Azure AD ACCESS token obtained via the
// client-credentials (service principal) flow and returns the verified
// identity (RD-1120).
//
// Unlike ExchangeCode — which validates an interactive id_token after a code
// exchange — this validates a token the client already holds: it checks the
// signature against Azure's JWKS, the expiry, and the audience. There is no
// nonce (client-credentials tokens carry none).
//
// The audience checked is the service-principal audience (the API resource the
// token was minted for), defaulting to the configured clientID.
//
// SECURITY: a successful return only proves the token is a valid, unexpired,
// correctly-audienced token signed by Azure for SOME tenant. The caller MUST
// still gate the returned TenantID against the tenant allowlist before
// trusting the identity — exactly as the authorization-code path does.
func (a *AzureADAuthenticator) VerifyAccessToken(ctx context.Context, rawAccessToken string) (*AzureIdentity, error) {
	if rawAccessToken == "" {
		return nil, errors.New("access token is empty")
	}

	audience := a.spAudience
	if audience == "" {
		audience = a.clientID
	}

	// Mirror ExchangeCode's issuer handling: multi-tenant endpoints emit tokens
	// whose issuer is the real per-tenant URL, not "common"/"organizations".
	skipIssuer := a.tenantID == "common" || a.tenantID == "organizations"
	verifier := a.provider.Verifier(&gooidc.Config{
		ClientID:        audience,
		SkipIssuerCheck: skipIssuer,
	})

	token, err := verifier.Verify(ctx, rawAccessToken)
	if err != nil {
		return nil, fmt.Errorf("access token verification failed: %w", err)
	}

	var claims struct {
		OID               string `json:"oid"`
		TenantID          string `json:"tid"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract access token claims: %w", err)
	}
	if claims.OID == "" {
		return nil, errors.New("oid claim missing from access token")
	}
	if claims.TenantID == "" {
		return nil, errors.New("tid claim missing from access token")
	}

	return &AzureIdentity{
		OID:               claims.OID,
		TenantID:          claims.TenantID,
		Email:             claims.Email,
		Name:              claims.Name,
		PreferredUsername: claims.PreferredUsername,
	}, nil
}

// AzureSubject returns the canonical subject for an Azure AD user.
// Format: "azuread:{oid}" — consistent with DID format used elsewhere.
func AzureSubject(oid string) string {
	return "azuread:" + oid
}

// NewAzureADAuthenticatorFromIssuer creates an authenticator using a custom
// OIDC issuer URL. This is intended for testing with mock OIDC servers; in
// production, use NewAzureADAuthenticator which derives the issuer from the
// tenant ID.
func NewAzureADAuthenticatorFromIssuer(clientID, clientSecret, issuerURL string) (*AzureADAuthenticator, error) {
	ctx := gooidc.InsecureIssuerURLContext(context.Background(), issuerURL)
	provider, err := gooidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC configuration: %w", err)
	}
	return &AzureADAuthenticator{
		clientID:     clientID,
		clientSecret: clientSecret,
		tenantID:     "test",
		provider:     provider,
	}, nil
}

func (a *AzureADAuthenticator) oauthConfig(redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     a.provider.Endpoint(),
		Scopes:       []string{gooidc.ScopeOpenID, "profile", "email"},
	}
}
