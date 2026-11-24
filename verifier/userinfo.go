// Copyright 2025 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
)

// UserInfoRequester enables the retrieval of user info from an OpenID Provider
// using the access token obtained during authentication. It uses the PK Token
// to look up the issuer URI for the OpenID Provider and ensure that the subject
// (sub claim) in the ID token matches the subject in the access token.
type UserInfoRequester struct {
	Issuer      string
	Subject     string
	AccessToken string
	HttpClient  *http.Client
}

func NewUserInfoRequester(pkt *pktoken.PKToken, accessToken string) (*UserInfoRequester, error) {
	if pkt == nil {
		return nil, fmt.Errorf("malformatted PK token claims: nil PK token")
	}
	// Read the issuer and subject from a single snapshot of the payload. Calling
	// pkt.Issuer() and pkt.Subject() separately re-parses the same mutable
	// payload twice and can pair one token's issuer with another token's subject
	// if the PK Token is replaced concurrently.
	var claims struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return nil, fmt.Errorf("malformatted PK token claims: %w", err)
	}
	if claims.Issuer == "" {
		return nil, fmt.Errorf("malformatted PK token claims: missing issuer")
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("malformatted PK token claims: missing subject")
	}
	return &UserInfoRequester{
		Issuer:      claims.Issuer,
		Subject:     claims.Subject,
		AccessToken: accessToken,
	}, nil
}

// Request calls an OpenID Provider's user info endpoint using the provided access token.
// The access token must match subject (sub claim) in the ID token issued alongside that
// access token. This function returns the user info JSON as a string.
func (ui *UserInfoRequester) Request(ctx context.Context) (string, error) {
	if ui == nil {
		return "", fmt.Errorf("nil UserInfoRequester")
	}
	if ui.Issuer == "" {
		return "", fmt.Errorf("userinfo request missing issuer")
	}
	if ui.Subject == "" {
		return "", fmt.Errorf("userinfo request missing subject")
	}
	if ui.AccessToken == "" {
		return "", fmt.Errorf("userinfo request missing access token")
	}

	httpClient := ui.HttpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	// Discovery and the userinfo call share the access token's issuer and are
	// performed as one operation. In particular, never retain a previous
	// response on the requester: every failure returns an empty result.
	userInfoEndpoint, err := discoverUserInfoEndpoint(ctx, httpClient, ui.Issuer)
	if err != nil {
		return "", err
	}
	userInfoJSON, err := fetchUserInfo(ctx, httpClient, userInfoEndpoint, ui.AccessToken)
	if err != nil {
		return "", err
	}
	if err := checkUserInfoIdentity(userInfoJSON, ui.Issuer, ui.Subject); err != nil {
		return "", err
	}

	// Return compact JSON, matching the previous API's output while preserving
	// every claim the provider returned (including claims OpenPubkey does not
	// know about).
	var compact bytes.Buffer
	if err := json.Compact(&compact, userInfoJSON); err != nil {
		return "", fmt.Errorf("failed to marshal userinfo response: %w", err)
	}
	return compact.String(), nil
}

func discoverUserInfoEndpoint(ctx context.Context, httpClient *http.Client, issuer string) (string, error) {
	discoveryURL := strings.TrimRight(strings.TrimSpace(issuer), "/")
	if !strings.Contains(discoveryURL, "://") {
		discoveryURL = "https://" + discoveryURL
	}
	discoveryURL += "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create OIDC discovery request for issuer %q: %w", issuer, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OIDC discovery document for issuer %q: %w", issuer, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery request for issuer %q failed: %s", issuer, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read OIDC discovery response for issuer %q: %w", issuer, err)
	}

	var discovery struct {
		Issuer           string `json:"issuer"`
		UserInfoEndpoint string `json:"userinfo_endpoint"`
	}
	if err := json.Unmarshal(body, &discovery); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}
	if discovery.Issuer == "" {
		return "", fmt.Errorf("OIDC discovery document for issuer %q is missing an issuer", issuer)
	}
	if !simpleoidc.SameIssuer(discovery.Issuer, issuer) {
		return "", fmt.Errorf("OIDC discovery issuer %q does not match requested issuer %q", discovery.Issuer, issuer)
	}
	if discovery.UserInfoEndpoint == "" {
		return "", fmt.Errorf("OIDC discovery document for issuer %q is missing a userinfo_endpoint", issuer)
	}
	endpoint, err := url.Parse(discovery.UserInfoEndpoint)
	if err != nil || !endpoint.IsAbs() || (endpoint.Scheme != "https" && endpoint.Scheme != "http") {
		return "", fmt.Errorf("OIDC discovery document for issuer %q has an invalid userinfo_endpoint", issuer)
	}
	return discovery.UserInfoEndpoint, nil
}

func fetchUserInfo(ctx context.Context, httpClient *http.Client, endpoint, accessToken string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read userinfo response: %w", err)
	}
	return body, nil
}

func checkUserInfoIdentity(userInfoJSON []byte, expectedIssuer, expectedSubject string) error {
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(userInfoJSON, &claims); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	subjectJSON, ok := claims["sub"]
	if !ok {
		return fmt.Errorf("userinfo response is missing the sub claim")
	}
	var subject string
	if err := json.Unmarshal(subjectJSON, &subject); err != nil {
		return fmt.Errorf("userinfo response has an invalid sub claim: %w", err)
	}
	if subject == "" {
		return fmt.Errorf("userinfo response has an empty sub claim")
	}
	if subject != expectedSubject {
		return fmt.Errorf("userinfo subject %q does not match expected subject %q", subject, expectedSubject)
	}

	// The iss claim is optional in a userinfo response. When a provider does
	// include it, make sure it identifies the same issuer we discovered the
	// endpoint from. SameIssuer accepts legal aliases for that issuer.
	if issuerJSON, ok := claims["iss"]; ok {
		var issuer string
		if err := json.Unmarshal(issuerJSON, &issuer); err != nil {
			return fmt.Errorf("userinfo response has an invalid iss claim: %w", err)
		}
		if issuer != "" && !simpleoidc.SameIssuer(issuer, expectedIssuer) {
			return fmt.Errorf("userinfo issuer %q does not match expected issuer %q", issuer, expectedIssuer)
		}
	}
	return nil
}
