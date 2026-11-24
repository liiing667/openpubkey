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
	"fmt"

	"github.com/awnumar/memguard"
	"github.com/openpubkey/openpubkey/discover"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

const gitlabIssuer = "https://gitlab.com"

// Claim names used by GitLab CI/CD OIDC ID Tokens. See
// https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html#token-payload
const (
	gitlabRepositoryClaim = "project_path"
	gitlabWorkflowClaim   = "ref"
	gitlabRefPathClaim    = "ref_path"
	gitlabAudienceClaim   = "aud"
)

type GitlabCiOp struct {
	issuer                    string // Change issuer to point this to a test issuer
	publicKeyFinder           discover.PublicKeyFinder
	tokenEnvVar               string
	requestTokensOverrideFunc func(string) (*simpleoidc.Tokens, error)
	// policy optionally restricts which projects, refs and audiences may
	// mint PK Tokens. When empty every well-formed token is accepted,
	// preserving the previous behavior.
	policy CIPolicy
}

func NewGitlabCiOpFromEnvironmentDefault(policyArgs ...any) *GitlabCiOp {
	return NewGitlabCiOpFromEnvironment("OPENPUBKEY_JWT", policyArgs...)
}

func NewGitlabCiOpFromEnvironment(tokenEnvVar string, policyArgs ...any) *GitlabCiOp {
	return NewGitlabCiOp(gitlabIssuer, tokenEnvVar, policyArgs...)
}

func NewGitlabCiOp(issuer string, tokenEnvVar string, policyArgs ...any) *GitlabCiOp {
	op := &GitlabCiOp{
		issuer:                    issuer,
		publicKeyFinder:           *discover.DefaultPubkeyFinder(),
		tokenEnvVar:               tokenEnvVar,
		requestTokensOverrideFunc: nil,
	}
	op.setPolicy(ciPolicyFromArgs(policyArgs...))
	return op
}

// NewGitlabCiOpWithPolicy creates a GitlabCiOp whose ID Tokens must satisfy
// policy before a PK Token is generated or verified. The claim names used by
// GitLab CI (project_path, ref and aud) are configured on the policy
// automatically; callers only supply the allowed values.
//
// LegacyAudienceClaim, if set on policy, keeps accepting tokens that carry
// the audience in an older, custom claim alongside the standard "aud" claim.
func NewGitlabCiOpWithPolicy(issuer string, tokenEnvVar string, policy any) *GitlabCiOp {
	op := NewGitlabCiOp(issuer, tokenEnvVar)
	op.setPolicy(ciPolicyFromArgs(policy))
	return op
}

// NewGitlabCiOpWithCIPolicy is an alias for NewGitlabCiOpWithPolicy.
func NewGitlabCiOpWithCIPolicy(issuer string, tokenEnvVar string, policy CIPolicy) *GitlabCiOp {
	return NewGitlabCiOpWithPolicy(issuer, tokenEnvVar, policy)
}

// NewGitlabCiOpFromEnvironmentWithPolicy creates a GitLab CI provider from the
// named environment variable and enforces policy on its ID Tokens.
func NewGitlabCiOpFromEnvironmentWithPolicy(tokenEnvVar string, policy CIPolicy) *GitlabCiOp {
	return NewGitlabCiOpFromEnvironment(tokenEnvVar, policy)
}

// NewGitlabCiOpFromEnvironmentDefaultWithPolicy creates a GitLab CI provider
// using the default OPENPUBKEY_JWT environment variable.
func NewGitlabCiOpFromEnvironmentDefaultWithPolicy(policy CIPolicy) *GitlabCiOp {
	return NewGitlabCiOpFromEnvironmentDefault(policy)
}

func (g *GitlabCiOp) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return g.publicKeyFinder.ByToken(ctx, g.issuer, token, true)
}

func (g *GitlabCiOp) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return g.publicKeyFinder.ByKeyID(ctx, g.issuer, keyID, true)
}

func (g *GitlabCiOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	// Define our commitment as the hash of the client instance claims
	cicHash, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}

	var idToken []byte
	if g.requestTokensOverrideFunc != nil {
		noCicHashInIDToken := ""
		if tokens, err := g.requestTokensOverrideFunc(noCicHashInIDToken); err != nil {
			return nil, fmt.Errorf("error requesting ID Token: %w", err)
		} else {
			idToken = tokens.IDToken
		}
	} else {
		idTokenStr, err := getEnvVar(g.tokenEnvVar)
		if err != nil {
			return nil, fmt.Errorf("error requesting ID Token: %w", err)
		}
		idToken = []byte(idTokenStr)
	}
	// idTokenLB is the ID Token in a memguard LockedBuffer, this is done
	// because the ID Token contains the OPs RSA signature which is a secret
	// in GQ signatures. For non-GQ signatures OPs RSA signature is considered
	// a public value.
	idTokenLB := memguard.NewBufferFromBytes(idToken)
	defer idTokenLB.Destroy()
	// Enforce the CI policy on the raw ID Token before the GQ bound
	// signature is created. A policy failure aborts RequestTokens and no PK
	// Token is produced, so a failed provider/policy switch cannot advance
	// the trust state of the run.
	if err := g.policy.CheckClaims(idTokenLB.Bytes()); err != nil {
		return nil, fmt.Errorf("GitLab CI ID Token rejected by CI policy: %w", err)
	}
	gqToken, err := CreateGQBoundToken(ctx, idTokenLB.Bytes(), g, string(cicHash))
	if err != nil {
		return nil, err
	}
	return &simpleoidc.Tokens{IDToken: gqToken}, nil
}

func (g *GitlabCiOp) Issuer() string {
	return g.issuer
}

func (g *GitlabCiOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	opts := ProviderVerifierOpts{CommitType: CommitTypesEnum.GQ_BOUND, GQOnly: true, SkipClientIDCheck: true}
	if g.publicKeyFinder.JwksFunc != nil {
		opts.DiscoverPublicKey = &g.publicKeyFinder
	}
	vp := NewProviderVerifier(g.issuer, opts)
	if err := vp.VerifyIDToken(ctx, idt, cic); err != nil {
		return err
	}
	// Re-check the CI policy at verification time so that a PK Token minted
	// by a project, ref or audience outside the allowlist is rejected even
	// when its GQ signature and commitment are valid.
	if err := g.policy.CheckClaims(idt); err != nil {
		return fmt.Errorf("GitLab CI PK Token rejected by CI policy: %w", err)
	}
	return nil
}

// Policy returns the CI policy configured on this GitLab CI provider.
func (g *GitlabCiOp) Policy() CIPolicy {
	return g.policy
}

// GetPolicy is an alias for Policy.
func (g *GitlabCiOp) GetPolicy() CIPolicy {
	return g.policy
}

// SetPolicy replaces the CI policy and fills in the GitLab CI claim names when
// the caller did not set them explicitly.
func (g *GitlabCiOp) SetPolicy(policy CIPolicy) {
	g.setPolicy(policy)
}

func (g *GitlabCiOp) setPolicy(policy CIPolicy) {
	if policy.RepositoryClaim == "" {
		policy.RepositoryClaim = gitlabRepositoryClaim
	}
	if policy.WorkflowClaim == "" {
		policy.WorkflowClaim = gitlabWorkflowClaim
	}
	if policy.LegacyWorkflowClaim == "" {
		policy.LegacyWorkflowClaim = gitlabRefPathClaim
	}
	if policy.AudienceClaim == "" {
		policy.AudienceClaim = gitlabAudienceClaim
	}
	g.policy = policy
}
