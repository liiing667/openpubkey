// Copyright 2026 OpenPubkey
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
	"encoding/json"
	"fmt"

	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/util"
)

// CIPolicy restricts which CI/CD jobs may mint PK Tokens through a CI
// provider (GitHub Actions, GitLab CI or Forgejo Actions). Every field that
// is set must match a claim in the ID Token before a PK Token is generated or
// accepted. An empty CIPolicy matches every token; this keeps existing
// deployments that do not pin a repository, workflow or audience working.
//
// The policy is enforced both at issuance, in the provider's RequestTokens,
// so a failing policy never advances the trust state of a run, and at
// verification, so a PK Token minted elsewhere is rejected unless it
// satisfies the same policy.
type CIPolicy struct {
	// Repositories is the allowlist of allowed repositories. The token is
	// accepted if its repository claim equals any entry in the list. An
	// empty list disables the repository check.
	//
	// Examples:
	//   - GitHub Actions: "octocat/demo" (the "repository" claim)
	//   - GitLab CI: "octocat/demo" (the "project_path" claim)
	//   - Forgejo Actions: "octocat/demo" (the "repository" claim)
	Repositories []string

	// Repository is a convenience alias for a single allowed repository. When
	// both Repository and Repositories are set, the token may match either.
	Repository any

	// AllowedRepositories is an alias for Repositories.
	AllowedRepositories []string

	// Workflows is the allowlist of allowed workflows. The token is accepted
	// if its workflow claim equals any entry in the list. An empty list
	// disables the workflow check.
	//
	// Examples:
	//   - GitHub Actions: "octocat/demo/.github/workflows/release.yml@refs/heads/main"
	//     (the "workflow" claim)
	//   - GitLab CI: "release" (the "ref" claim; GitLab CI ID Tokens do not
	//     carry a dedicated workflow name)
	//   - Forgejo Actions: the workflow file, e.g.
	//     "octocat/demo/.forgejo/workflows/release.yml" (the "workflow" claim)
	Workflows []string

	// Workflow is a convenience alias for a single allowed workflow. When
	// both Workflow and Workflows are set, the token may match either.
	Workflow any

	// AllowedWorkflows is an alias for Workflows.
	AllowedWorkflows []string

	// Audiences is the allowlist of allowed ID Token audiences. The token is
	// accepted if its audience claim equals any entry in the list. An empty
	// list disables the audience check.
	//
	// Note that the commitment placed in the audience claim (for GitHub and
	// Forgejo) or the GQ commitment prefix (for GitLab) is checked
	// separately by the ProviderVerifier and is not part of this list.
	Audiences []string

	// Audience is a convenience alias for a single allowed audience. When
	// both Audience and Audiences are set, the token may match either.
	Audience any

	// AllowedAudiences is an alias for Audiences.
	AllowedAudiences []string

	// RepositoryClaim is the payload claim name holding the repository,
	// e.g. "repository" or "project_path". Empty disables repository
	// matching even when Repositories is set.
	RepositoryClaim string

	// LegacyRepositoryClaim optionally names an additional, older claim in
	// which the repository may be carried.
	LegacyRepositoryClaim string

	// WorkflowClaim is the payload claim name holding the workflow, e.g.
	// "workflow" or "ref". Empty disables workflow matching even when
	// Workflows is set.
	WorkflowClaim string

	// LegacyWorkflowClaim optionally names an additional, older claim in
	// which the workflow may be carried.
	LegacyWorkflowClaim string

	// AudienceClaim is the payload claim name holding the audience. It
	// defaults to "aud". Older GitLab CI deployments used a custom
	// audience claim name; set this to that claim name to keep accepting
	// those tokens.
	AudienceClaim string

	// LegacyAudienceClaim optionally names an additional, older claim in
	// which the audience may be carried. A token is accepted when either
	// AudienceClaim (or "aud" by default) or LegacyAudienceClaim contains an
	// allowed audience. This preserves compatibility with the old GitLab CI
	// claim style without weakening the "aud" check for new tokens.
	LegacyAudienceClaim string
}

// CIProviderPolicy, GithubActionsPolicy, GitlabCIPolicy and
// ForgejoActionsPolicy are aliases for CIPolicy, named for the CI provider
// they constrain.
type CIProviderPolicy = CIPolicy
type CIProviderPolicyOpts = CIPolicy
type CIPolicyOpts = CIPolicy
type GithubActionsPolicy = CIPolicy
type GithubPolicy = CIPolicy
type GitlabCIPolicy = CIPolicy
type GitlabPolicy = CIPolicy
type ForgejoActionsPolicy = CIPolicy
type ForgejoPolicy = CIPolicy

// repositories returns the configured repository allowlist, combining the
// plural allowlist with the single-value convenience field.
func (p CIPolicy) repositories() []string {
	return ciPolicyAppendNonEmpty(append(p.Repositories, p.AllowedRepositories...), p.Repository)
}

// workflows returns the configured workflow allowlist, combining the plural
// allowlist with the single-value convenience field.
func (p CIPolicy) workflows() []string {
	return ciPolicyAppendNonEmpty(append(p.Workflows, p.AllowedWorkflows...), p.Workflow)
}

// audiences returns the configured audience allowlist, combining the plural
// allowlist with the single-value convenience field.
func (p CIPolicy) audiences() []string {
	return ciPolicyAppendNonEmpty(append(p.Audiences, p.AllowedAudiences...), p.Audience)
}

func ciPolicyAppendNonEmpty(values []string, extra any) []string {
	switch value := extra.(type) {
	case nil:
		return values
	case string:
		if value == "" {
			return values
		}
		values = append(values, value)
	case []string:
		values = append(values, value...)
	default:
		// Ignore unsupported convenience values rather than panicking; the
		// explicit allowlist fields remain authoritative.
	}
	return values
}

// Empty reports whether the policy constrains anything. An empty policy is
// the backward-compatible default that accepts every well-formed token.
func (p CIPolicy) Empty() bool {
	return len(p.repositories()) == 0 && len(p.workflows()) == 0 && len(p.audiences()) == 0
}

// CheckClaims validates the ID Token payload claims against the policy. It
// returns nil when every configured constraint is satisfied and a
// descriptive error otherwise. The token is only parsed; its signature is
// verified independently by the ProviderVerifier.
func (p CIPolicy) CheckClaims(idToken any) error {
	if p.Empty() {
		return nil
	}

	claims, err := ciPolicyClaims(idToken)
	if err != nil {
		return err
	}

	if repositories := p.repositories(); len(repositories) > 0 {
		if p.RepositoryClaim == "" {
			return fmt.Errorf("CI policy requires a repository but no repository claim is configured")
		}
		if err := checkAllowlistWithLegacy(claims, p.RepositoryClaim, p.LegacyRepositoryClaim, repositories, "repository"); err != nil {
			return err
		}
	}

	if workflows := p.workflows(); len(workflows) > 0 {
		if p.WorkflowClaim == "" {
			return fmt.Errorf("CI policy requires a workflow but no workflow claim is configured")
		}
		if err := checkAllowlistWithLegacy(claims, p.WorkflowClaim, p.LegacyWorkflowClaim, workflows, "workflow"); err != nil {
			return err
		}
	}

	if audiences := p.audiences(); len(audiences) > 0 {
		audienceClaim := p.AudienceClaim
		if audienceClaim == "" {
			audienceClaim = "aud"
		}
		if err := checkAllowlistWithLegacy(claims, audienceClaim, p.LegacyAudienceClaim, audiences, "audience"); err != nil {
			return err
		}
	}

	return nil
}

// ciPolicyClaims extracts the payload claims from an ID Token in compact or
// string form, or accepts an already-decoded claim map. This keeps
// CheckClaims usable both by providers that hold raw tokens and by callers
// that have already parsed the payload.
func ciPolicyClaims(idToken any) (map[string]any, error) {
	var claims map[string]any
	switch value := idToken.(type) {
	case map[string]any:
		return value, nil
	case string:
		return ciPolicyClaims([]byte(value))
	case []byte:
		idt, err := oidc.NewJwt(value)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ID Token for CI policy check: %w", err)
		}
		payload, err := util.Base64DecodeForJWT([]byte(idt.GetPayload()))
		if err != nil {
			return nil, fmt.Errorf("failed to decode ID Token payload for CI policy check: %w", err)
		}
		if err := json.Unmarshal(payload, &claims); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ID Token claims for CI policy check: %w", err)
		}
		return claims, nil
	case *oidc.Jwt:
		if value == nil {
			return nil, fmt.Errorf("failed to parse ID Token for CI policy check: nil JWT")
		}
		payload, err := util.Base64DecodeForJWT([]byte(value.GetPayload()))
		if err != nil {
			return nil, fmt.Errorf("failed to decode ID Token payload for CI policy check: %w", err)
		}
		if err := json.Unmarshal(payload, &claims); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ID Token claims for CI policy check: %w", err)
		}
		return claims, nil
	default:
		return nil, fmt.Errorf("unsupported ID Token type for CI policy check: %T", idToken)
	}
}

// merge combines two policies. Allowlists are unioned and claim names from
// other take precedence only when they are set.
func (p CIPolicy) merge(other CIPolicy) CIPolicy {
	p.Repositories = append(p.Repositories, other.Repositories...)
	p.AllowedRepositories = append(p.AllowedRepositories, other.AllowedRepositories...)
	p.Workflows = append(p.Workflows, other.Workflows...)
	p.AllowedWorkflows = append(p.AllowedWorkflows, other.AllowedWorkflows...)
	p.Audiences = append(p.Audiences, other.Audiences...)
	p.AllowedAudiences = append(p.AllowedAudiences, other.AllowedAudiences...)
	if other.Repository != nil {
		p.Repository = other.Repository
	}
	if other.Workflow != nil {
		p.Workflow = other.Workflow
	}
	if other.Audience != nil {
		p.Audience = other.Audience
	}
	if other.RepositoryClaim != "" {
		p.RepositoryClaim = other.RepositoryClaim
	}
	if other.LegacyRepositoryClaim != "" {
		p.LegacyRepositoryClaim = other.LegacyRepositoryClaim
	}
	if other.WorkflowClaim != "" {
		p.WorkflowClaim = other.WorkflowClaim
	}
	if other.LegacyWorkflowClaim != "" {
		p.LegacyWorkflowClaim = other.LegacyWorkflowClaim
	}
	if other.AudienceClaim != "" {
		p.AudienceClaim = other.AudienceClaim
	}
	if other.LegacyAudienceClaim != "" {
		p.LegacyAudienceClaim = other.LegacyAudienceClaim
	}
	return p
}

// withDefaultClaims fills in the CI provider's standard claim names when the
// policy did not specify them, so a policy can be attached at the verifier
// level without repeating provider-specific claim names.
func (p CIPolicy) withDefaultClaims(issuer string) CIPolicy {
	repositoryClaim, workflowClaim, legacyWorkflowClaim, audienceClaim := "", "", "", "aud"
	switch {
	case issuer == githubIssuer:
		repositoryClaim = githubRepositoryClaim
		workflowClaim = githubWorkflowClaim
		legacyWorkflowClaim = githubWorkflowRefClaim
	case IsForgejoIssuer(issuer):
		repositoryClaim = forgejoRepositoryClaim
		workflowClaim = forgejoWorkflowClaim
		legacyWorkflowClaim = forgejoWorkflowRefClaim
	case issuer == gitlabIssuer:
		repositoryClaim = gitlabRepositoryClaim
		workflowClaim = gitlabWorkflowClaim
		legacyWorkflowClaim = gitlabRefPathClaim
	}
	if p.RepositoryClaim == "" {
		p.RepositoryClaim = repositoryClaim
	}
	if p.WorkflowClaim == "" {
		p.WorkflowClaim = workflowClaim
	}
	if p.LegacyWorkflowClaim == "" {
		p.LegacyWorkflowClaim = legacyWorkflowClaim
	}
	if p.AudienceClaim == "" {
		p.AudienceClaim = audienceClaim
	}
	return p
}

// Check is an alias for CheckClaims.
func (p CIPolicy) Check(idToken any) error {
	return p.CheckClaims(idToken)
}

// Validate is an alias for CheckClaims.
func (p CIPolicy) Validate(idToken any) error {
	return p.CheckClaims(idToken)
}

// checkAllowlistWithLegacy checks claimName first. If it does not match and
// legacyClaimName is set, it retries with the legacy claim so deployments
// that still emit the old claim spelling keep working.
func checkAllowlistWithLegacy(claims map[string]any, claimName string, legacyClaimName string, allowed []string, label string) error {
	err := checkAllowlist(claims, claimName, allowed, label)
	if err == nil {
		return nil
	}
	legacyNames := ciPolicyLegacyClaimNames(claimName)
	if legacyClaimName != "" {
		legacyNames = append([]string{legacyClaimName}, legacyNames...)
	}
	for _, name := range legacyNames {
		if name == "" || name == claimName {
			continue
		}
		if legacyErr := checkAllowlist(claims, name, allowed, label); legacyErr == nil {
			return nil
		}
	}
	if len(legacyNames) == 0 {
		return err
	}
	return fmt.Errorf("%w; legacy claim %q check also failed", err, legacyNames[0])
}

// ciPolicyLegacyClaimNames lists older spellings of the same claim that providers
// have emitted historically.
func ciPolicyLegacyClaimNames(claimName string) []string {
	switch claimName {
	case "workflow":
		return []string{"workflow_ref", "job_workflow_ref"}
	case "ref":
		return []string{"ref_path", "ci_config_ref_uri", "ci_config_ref"}
	case "aud":
		return []string{"audience"}
	}
	return nil
}

// checkAllowlist verifies that the string-valued claim claimName is present
// and matches one of the allowed values.
func checkAllowlist(claims map[string]any, claimName string, allowed []string, label string) error {
	value, ok := claims[claimName]
	if !ok {
		return fmt.Errorf("CI policy requires %s claim %q but it is missing from the ID Token", label, claimName)
	}
	switch valueValue := value.(type) {
	case string:
		return ciPolicyCheckAllowedString(valueValue, allowed, label, claimName)
	case []string:
		for _, entry := range valueValue {
			if ciPolicyContains(allowed, entry) {
				return nil
			}
		}
		return fmt.Errorf("CI policy rejected %s %q: none of %v are in allowlist %v", label, claimName, valueValue, allowed)
	case []any:
		var entries []string
		for _, entry := range valueValue {
			entryStr, ok := entry.(string)
			if !ok {
				return fmt.Errorf("CI policy %s claim %q must contain only strings, got %T", label, claimName, entry)
			}
			entries = append(entries, entryStr)
			if ciPolicyContains(allowed, entryStr) {
				return nil
			}
		}
		return fmt.Errorf("CI policy rejected %s %q: none of %v are in allowlist %v", label, claimName, entries, allowed)
	default:
		return fmt.Errorf("CI policy %s claim %q must be a string, got %T", label, claimName, value)
	}
}

func ciPolicyCheckAllowedString(value string, allowed []string, label string, claimName string) error {
	if ciPolicyContains(allowed, value) {
		return nil
	}
	return fmt.Errorf("CI policy rejected %s %q: not in allowlist %v", label, value, allowed)
}

func ciPolicyContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// ciPolicyFromArgs extracts an optional policy from constructor arguments. It
// accepts a CIPolicy, a *CIPolicy, or an option function that mutates a
// CIPolicy. Other argument types are ignored so constructors can be extended
// without breaking existing callers.
func ciPolicyFromArgs(args ...any) CIPolicy {
	var policy CIPolicy
	for _, arg := range args {
		switch value := arg.(type) {
		case CIPolicy:
			policy = value
		case *CIPolicy:
			if value != nil {
				policy = *value
			}
		case func(*CIPolicy):
			value(&policy)
		}
	}
	return policy
}

// CIPolicyProvider is implemented by CI providers that can expose the CI
// policy they enforce.
type CIPolicyProvider interface {
	Policy() CIPolicy
}
