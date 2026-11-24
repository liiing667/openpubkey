// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/awnumar/memguard"
	"github.com/openpubkey/openpubkey/discover"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

const githubIssuer = "https://token.actions.githubusercontent.com"

// Claim names used by GitHub Actions OIDC ID Tokens. See
// https://docs.github.com/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
const (
	githubRepositoryClaim  = "repository"
	githubWorkflowClaim    = "workflow"
	githubWorkflowRefClaim = "workflow_ref"
	githubAudienceClaim    = "aud"
)

type GithubOp struct {
	issuer                    string // Change issuer to point this to a test issuer
	rawTokenRequestURL        string
	tokenRequestAuthToken     string
	publicKeyFinder           discover.PublicKeyFinder
	requestTokensOverrideFunc func(string) (*simpleoidc.Tokens, error)
	// policy optionally restricts which repositories, workflows and
	// audiences may mint PK Tokens. When empty every well-formed token is
	// accepted, preserving the previous behavior.
	policy CIPolicy
}

var _ OpenIdProvider = (*GithubOp)(nil)

func NewGithubOpFromEnvironment(policyArgs ...any) (*GithubOp, error) {
	tokenURL, err := getEnvVar("ACTIONS_ID_TOKEN_REQUEST_URL")
	if err != nil {
		return nil, err
	}
	token, err := getEnvVar("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if err != nil {
		return nil, err
	}

	return NewGithubOp(tokenURL, token, policyArgs...), nil
}

func NewGithubOp(tokenURL string, token string, policyArgs ...any) *GithubOp {
	op := &GithubOp{
		issuer:                    githubIssuer,
		rawTokenRequestURL:        tokenURL,
		tokenRequestAuthToken:     token,
		publicKeyFinder:           *discover.DefaultPubkeyFinder(),
		requestTokensOverrideFunc: nil,
	}
	op.setPolicy(ciPolicyFromArgs(policyArgs...))
	return op
}

// NewGithubOpWithPolicy creates a GithubOp whose ID Tokens must satisfy
// policy before a PK Token is generated or verified. The claim names used by
// GitHub Actions (repository, workflow and aud) are configured on the policy
// automatically; callers only supply the allowed values.
func NewGithubOpWithPolicy(tokenURL string, token string, policy any) *GithubOp {
	op := NewGithubOp(tokenURL, token)
	op.setPolicy(ciPolicyFromArgs(policy))
	return op
}

// NewGithubOpWithCIPolicy is an alias for NewGithubOpWithPolicy.
func NewGithubOpWithCIPolicy(tokenURL string, token string, policy CIPolicy) *GithubOp {
	return NewGithubOpWithPolicy(tokenURL, token, policy)
}

// NewGithubOpFromEnvironmentWithPolicy creates a GitHub Actions provider from
// the runner environment and enforces policy on its ID Tokens.
func NewGithubOpFromEnvironmentWithPolicy(policy CIPolicy) (*GithubOp, error) {
	return NewGithubOpFromEnvironment(policy)
}

func buildTokenURL(rawTokenURL, audience string) (string, error) {
	parsedURL, err := url.Parse(rawTokenURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	if audience == "" {
		return "", fmt.Errorf("audience is required")
	}

	query := parsedURL.Query()
	query.Set("audience", audience)
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String(), nil
}

func (g *GithubOp) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return g.publicKeyFinder.ByToken(ctx, g.issuer, token, true)
}

func (g *GithubOp) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return g.publicKeyFinder.ByKeyID(ctx, g.issuer, keyID, true)
}

func (g *GithubOp) requestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error) {
	if g.requestTokensOverrideFunc != nil {
		tokens, err := g.requestTokensOverrideFunc(cicHash)
		if err != nil {
			return nil, fmt.Errorf("error requesting ID Token: %w", err)
		}
		return memguard.NewBufferFromBytes(tokens.IDToken), nil
	}

	tokenURL, err := buildTokenURL(g.rawTokenRequestURL, cicHash)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Authorization", "Bearer "+g.tokenRequestAuthToken)

	var httpClient http.Client
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 from jwt api: %s", http.StatusText(response.StatusCode))
	}

	rawBody, err := memguard.NewBufferFromEntireReader(response.Body)
	if err != nil {
		return nil, err
	}
	defer rawBody.Destroy()

	var jwt struct {
		Value json.RawMessage
	}
	err = json.Unmarshal(rawBody.Bytes(), &jwt)
	if err != nil {
		return nil, err
	}
	defer memguard.WipeBytes([]byte(jwt.Value))

	// json.RawMessage leaves the " (quotes) on the string. We need to remove the quotes
	return memguard.NewBufferFromBytes(jwt.Value[1 : len(jwt.Value)-1]), nil
}

func (g *GithubOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	// Define our commitment as the hash of the client instance claims
	commitment, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}

	// Use the commitment nonce to complete the OIDC flow and get an ID token from the provider
	idTokenLB, err := g.requestTokens(ctx, string(commitment))
	// idTokenLB is the ID Token in a memguard LockedBuffer, this is done
	// because the ID Token contains the OPs RSA signature which is a secret
	// in GQ signatures. For non-GQ signatures OPs RSA signature is considered
	// a public value.
	if err != nil {
		return nil, fmt.Errorf("error requesting ID Token: %w", err)
	}
	defer idTokenLB.Destroy()
	// Enforce the CI policy on the raw ID Token before the GQ signature is
	// created. If the policy fails we return an error and never produce a
	// PK Token, so a failed provider/policy switch cannot advance the trust
	// state of the run.
	if err := g.policy.CheckClaims(idTokenLB.Bytes()); err != nil {
		return nil, fmt.Errorf("GitHub Actions ID Token rejected by CI policy: %w", err)
	}
	gqToken, err := CreateGQToken(ctx, idTokenLB.Bytes(), g)

	return &simpleoidc.Tokens{IDToken: gqToken}, err
}

func (g *GithubOp) Issuer() string {
	return g.issuer
}

func (g *GithubOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	opts := ProviderVerifierOpts{CommitType: CommitTypesEnum.AUD_CLAIM, GQOnly: true, SkipClientIDCheck: true}
	if g.publicKeyFinder.JwksFunc != nil {
		opts.DiscoverPublicKey = &g.publicKeyFinder
	}
	vp := NewProviderVerifier(g.issuer, opts)
	if err := vp.VerifyIDToken(ctx, idt, cic); err != nil {
		return err
	}
	// Re-check the CI policy at verification time so that a PK Token minted
	// by a repository, workflow or audience outside the allowlist is
	// rejected even when its signature and commitment are valid.
	if err := g.policy.CheckClaims(idt); err != nil {
		return fmt.Errorf("GitHub Actions PK Token rejected by CI policy: %w", err)
	}
	return nil
}

// Policy returns the CI policy configured on this GitHub Actions provider.
func (g *GithubOp) Policy() CIPolicy {
	return g.policy
}

// GetPolicy is an alias for Policy.
func (g *GithubOp) GetPolicy() CIPolicy {
	return g.policy
}

// SetPolicy replaces the CI policy and fills in the GitHub Actions claim names
// when the caller did not set them explicitly.
func (g *GithubOp) SetPolicy(policy CIPolicy) {
	g.setPolicy(policy)
}

func (g *GithubOp) setPolicy(policy CIPolicy) {
	if policy.RepositoryClaim == "" {
		policy.RepositoryClaim = githubRepositoryClaim
	}
	if policy.WorkflowClaim == "" {
		policy.WorkflowClaim = githubWorkflowClaim
	}
	if policy.LegacyWorkflowClaim == "" {
		policy.LegacyWorkflowClaim = githubWorkflowRefClaim
	}
	if policy.AudienceClaim == "" {
		policy.AudienceClaim = githubAudienceClaim
	}
	g.policy = policy
}
