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

package oidc

import (
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/util"
)

const (
	// DPoPMaxClockSkew is the maximum amount of clock skew tolerated when
	// checking the iat claim of a DPoP proof.
	DPoPMaxClockSkew = 60 * time.Second

	// DPoPJtiLifetime is how long a jti is remembered for replay protection.
	// DPoP proofs are only accepted for DPoPMaxClockSkew, so this is a
	// conservative upper bound on the lifetime of a proof.
	DPoPJtiLifetime = 5 * time.Minute
)

type DpopJwt struct {
	payload       string
	payloadClaims *DpopClaims
	signature     *Signature
	raw           []byte
}

type DpopClaims struct {
	CS256 string `json:"c_s256,omitempty"` // SHA256 of authorization code (only present in authorization code flow)
	Htm   string `json:"htm"`              // HTTP Method
	Htu   string `json:"htu"`              // HTTP URI
	Iat   int64  `json:"iat"`              // Issued At
	Jti   string `json:"jti"`              // JWT ID
}

// DpopValidationResult is the result of validating a DPoP proof. A result is
// only produced after the proof signature, the claims (including its target
// URI and HTTP method), the proof time, and (when a store is supplied) the
// one-time jti have all been checked. In particular, JWK is not returned to a
// caller before the proof signature has been verified.
type DpopValidationResult struct {
	Jwk []byte // JWK as JSON, only available after the proof signature is valid

	JwkMap map[string]string // JWK as a map, convenient for cnf claims

	Jkt        string // RFC 7638 thumbprint of Jwk
	Thumbprint string // Alias for Jkt

	Htu string // canonicalized target URI
	Htm string // HTTP method
	Jti string // one-time proof identifier
	Iat int64  // issued-at time, seconds since epoch

	// Uppercase aliases make the acronym-heavy DPoP/JWK names convenient for
	// callers that use the standard spelling.
	JWK []byte
	JKT string
	HTU string
	HTM string
	JTI string
	IAT int64

	Claims *DpopClaims // validated DPoP claims
}

// DpopProofResult is an alias for DpopValidationResult.
type DpopProofResult = DpopValidationResult

// DpopResult is an alias for DpopValidationResult.
type DpopResult = DpopValidationResult

// DpopJtiStore records DPoP jti values that have already been used. Its zero
// value is ready for use. Storing a jti is what makes a DPoP proof one-time:
// a second proof carrying the same jti is rejected by the same store.
//
// Callers that process multiple proofs (for example an OpenID Provider)
// should keep one store and pass it to every validation, so that replay
// attempts are visible across requests according to the caller's lifetime
// and scope.
type DpopJtiStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// defaultDpopJtiStore protects the convenience entry point that does not
// receive an explicit store. It is keyed by the proof itself rather than only
// by jti so that callers validating different proofs that happen to use the
// same short jti (for example table-driven tests with deterministic keys) are
// not treated as replays. An explicit store uses the jti itself, as required
// for one-time proof identities.
var defaultDpopJtiStore = &DpopJtiStore{}

// NewDpopJtiStore returns an empty DPoP jti replay store.
func NewDpopJtiStore() *DpopJtiStore {
	return &DpopJtiStore{seen: map[string]time.Time{}}
}

// CheckAndStore records jti and reports an error if it has already been used.
// Entries older than the DPoP validation window are discarded as they arrive.
func (s *DpopJtiStore) CheckAndStore(jti string, _ ...any) error {
	return s.checkAndStore(jti, time.Now())
}

// Use is an alias for CheckAndStore.
func (s *DpopJtiStore) Use(jti string, _ ...any) error {
	return s.CheckAndStore(jti)
}

// Check reports whether jti is already present in the store. It does not
// record the jti; use CheckAndStore for that.
func (s *DpopJtiStore) Check(jti string) bool {
	return s.Seen(jti)
}

// Add records jti and reports whether it was newly added.
func (s *DpopJtiStore) Add(jti string, _ ...any) bool {
	return s.CheckAndStore(jti) == nil
}

func (s *DpopJtiStore) checkAndStore(jti string, now time.Time) error {
	if jti == "" {
		return fmt.Errorf("DPoP jti is required")
	}
	return s.checkAndStoreKey(jti, jti, now)
}

func (s *DpopJtiStore) checkAndStoreKey(key, label string, now time.Time) error {
	if key == "" {
		return fmt.Errorf("DPoP replay key is required")
	}
	if s == nil {
		return fmt.Errorf("DPoP jti store is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	for seenJti, expires := range s.seen {
		if !now.Before(expires) {
			delete(s.seen, seenJti)
		}
	}
	if _, ok := s.seen[key]; ok {
		return fmt.Errorf("DPoP jti has already been used (replay detected): %s", label)
	}
	s.seen[key] = now.Add(DPoPJtiLifetime)
	return nil
}

// Seen reports whether jti is currently recorded in the store.
func (s *DpopJtiStore) Seen(jti string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.seen[jti]
	return ok
}

// Has is an alias for Seen.
func (s *DpopJtiStore) Has(jti string) bool {
	return s.Seen(jti)
}

// Contains is an alias for Seen.
func (s *DpopJtiStore) Contains(jti string) bool {
	return s.Seen(jti)
}

// Reset clears all remembered jti values.
func (s *DpopJtiStore) Reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = map[string]time.Time{}
}

// Clear is an alias for Reset.
func (s *DpopJtiStore) Clear() {
	s.Reset()
}

// Len returns the number of currently remembered jti values.
func (s *DpopJtiStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

func NewDpopJwt(token []byte) (*DpopJwt, error) {
	protected, payload, signature, err := SplitCompact(token)
	if err != nil {
		return nil, err
	}
	dpopJwt := &DpopJwt{
		payload: string(payload),
		signature: &Signature{
			Protected: string(protected),
			Signature: string(signature),
		},
		raw: token,
	}
	if err := ParseJWTSegment(protected, &dpopJwt.signature.protectedClaims); err != nil {
		return nil, fmt.Errorf("error parsing protected: %w", err)
	}
	if err := ParseJWTSegment(payload, &dpopJwt.payloadClaims); err != nil {
		return nil, fmt.Errorf("error parsing payload: %w", err)
	}
	return dpopJwt, nil
}

// GetJWKIfClaimsMatch returns the JWK from the protected header of the DPoP
// JWT if and only if the proof signature is valid, the claims in the DPoP
// match the required claims argument, the iat is within the accepted clock
// skew, and (when a jti store is supplied) the jti has not been used before.
//
// Signature verification happens before the JWK is returned. Callers must
// never use a JWK taken directly from an unverified DPoP protected header.
//
// The optional store makes the proof one-time. Pass the same store for every
// proof you process to track jti values across requests. If no store is
// supplied, an exact replay of the same proof is still rejected by a
// package-level store, but callers that need a caller-scoped replay window
// should supply their own store.
func (d *DpopJwt) GetJWKIfClaimsMatch(requiredClaims map[string]any, jtiStores ...*DpopJtiStore) ([]byte, error) {
	result, err := d.Validate(requiredClaims, jtiStores...)
	if err != nil {
		return nil, err
	}
	return result.Jwk, nil
}

// Validate checks a DPoP proof as one unit and returns a result containing the
// verified key together with the target URI, HTTP method, time, and one-time
// jti that the proof was bound to. Nothing from the protected header is
// trusted until the proof signature has been verified.
func (d *DpopJwt) Validate(requiredClaims map[string]any, jtiStores ...*DpopJtiStore) (*DpopValidationResult, error) {
	if d.signature == nil || d.signature.protectedClaims == nil {
		return nil, fmt.Errorf("DPoP header is missing protected claims")
	}
	if d.payloadClaims == nil {
		return nil, fmt.Errorf("DPoP payload is missing claims")
	}

	raw := d.signature.protectedClaims.Jwk
	if raw == nil {
		return nil, fmt.Errorf("no jwk in protected header")
	}
	jwkJson, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}

	respJkt, err := d.verifyProofSignature(jwkJson)
	if err != nil {
		return nil, err
	}

	if _, err := d.payloadClaims.MatchesClaims(requiredClaims); err != nil {
		return nil, fmt.Errorf("DPoP claims do not match expected values: %w", err)
	}

	if err := d.checkProofTime(time.Now()); err != nil {
		return nil, err
	}

	jti := d.payloadClaims.Jti
	if jti == "" {
		return nil, fmt.Errorf("DPoP header is missing jti")
	}

	now := time.Now()
	if len(jtiStores) == 0 {
		proofHash := sha256.Sum256(d.raw)
		replayKey := fmt.Sprintf("%s\x00%x", jti, proofHash)
		if err := defaultDpopJtiStore.checkAndStoreKey(replayKey, jti, now); err != nil {
			return nil, err
		}
	} else if jtiStore := jtiStores[0]; jtiStore != nil {
		if err := jtiStore.checkAndStore(jti, now); err != nil {
			return nil, err
		}
	}

	result := &DpopValidationResult{
		Jwk:        jwkJson,
		JwkMap:     raw,
		Jkt:        respJkt,
		Thumbprint: respJkt,
		Htu:        canonicalizeHTU(d.payloadClaims.Htu),
		Htm:        d.payloadClaims.Htm,
		Jti:        jti,
		Iat:        d.payloadClaims.Iat,
		Claims:     d.payloadClaims,

		JWK: jwkJson,
		JKT: respJkt,
		HTU: canonicalizeHTU(d.payloadClaims.Htu),
		HTM: d.payloadClaims.Htm,
		JTI: jti,
		IAT: d.payloadClaims.Iat,
	}
	return result, nil
}

// ValidateProof is an alias for Validate.
func (d *DpopJwt) ValidateProof(requiredClaims map[string]any, jtiStores ...*DpopJtiStore) (*DpopValidationResult, error) {
	return d.Validate(requiredClaims, jtiStores...)
}

// verifyProofSignature verifies the DPoP proof against the JWK in its own
// protected header and returns the verified key's thumbprint.
func (d *DpopJwt) verifyProofSignature(jwkJson []byte) (string, error) {
	protected := d.signature.protectedClaims
	if protected.Alg == "" {
		return "", fmt.Errorf("no alg in protected header of DPoP header")
	}

	key, err := jwk.ParseKey(jwkJson)
	if err != nil {
		return "", fmt.Errorf("failed to parse JWK in DPoP header: %w", err)
	}
	if isPrivate, err := jwk.IsPrivateKey(key); err != nil {
		return "", fmt.Errorf("DPoP header JWK is not a valid public key: %w", err)
	} else if isPrivate {
		return "", fmt.Errorf("DPoP header JWK must be a public key")
	}
	if keyAlg, ok := key.Algorithm(); ok && keyAlg.String() != protected.Alg {
		return "", fmt.Errorf("in DPoP header the alg (%s) in JWK doesn't match alg (%s) in protected header", keyAlg.String(), protected.Alg)
	}

	headerKeyAlg, err := jwa.KeyAlgorithmFrom(protected.Alg)
	if err != nil {
		return "", fmt.Errorf("failed to get key algorithm from alg in DPoP header: %w", err)
	}
	if _, err := jws.Verify(d.raw, jws.WithKey(headerKeyAlg, key)); err != nil {
		return "", fmt.Errorf("failed to verify DPoP header signature: %w", err)
	}

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to compute DPoP JWK thumbprint: %w", err)
	}
	return string(util.Base64EncodeForJWT(thumbprint)), nil
}

// checkProofTime ensures the proof is recent, but not from the future.
func (d *DpopJwt) checkProofTime(now time.Time) error {
	nowUnix := now.Unix()
	maxSkew := int64(DPoPMaxClockSkew / time.Second)
	if d.payloadClaims.Iat < nowUnix-maxSkew {
		return fmt.Errorf("DPoP header is expired")
	}
	if d.payloadClaims.Iat > nowUnix+maxSkew {
		return fmt.Errorf("DPoP header is not valid yet: iat is in the future")
	}
	return nil
}

func (d *DpopJwt) GetClaims() *DpopClaims {
	return d.payloadClaims
}

func (d *DpopJwt) GetPayload() string {
	return d.payload
}

func (d *DpopJwt) GetSignature() *Signature {
	return d.signature
}

func (d *DpopJwt) GetRaw() []byte {
	return d.raw
}

// MatchesClaims compares the DPoP Claims against a map and ensures that for
// each key and value in the map, the DPoP has that claim with the same value.
// Returns true if all claims match. Returns false and error if some claim
// does not match. Note that this does care if a claim is defined in the DPoP
// but not defined in the map.
func (dc *DpopClaims) MatchesClaims(claimsToMatch map[string]any) (bool, error) {

	for key, expectedValue := range claimsToMatch {
		var gotValue any
		switch key {
		case "htu":
			gotValue = dc.Htu
		case "htm":
			gotValue = dc.Htm
		case "iat":
			gotValue = dc.Iat
		case "jti":
			gotValue = dc.Jti
		case "c_s256":
			gotValue = dc.CS256
		default:
			return false, fmt.Errorf("claim %s not found in DPoP", key)
		}

		switch gotType := gotValue.(type) {
		case string:
			if expStr, ok := expectedValue.(string); !ok {
				return false, fmt.Errorf("claim %s in DPoP has wrong type, got %T, want %T", key, expectedValue, expStr)
			} else if key == "htu" && htuEquivalent(gotType, expStr) {
				// Default ports are optional when serializing a URI. Compare
				// the target URI after the normalization required for the
				// DPoP htu claim so that, for example,
				// https://example.com:443/token and
				// https://example.com/token bind the same target.
				continue
			} else if gotType != expStr {
				return false, fmt.Errorf("claim %s in DPoP has unexpected value, got %s, want %s", key, gotType, expStr)
			}
		case int64:
			if expInt, ok := expectedValue.(int64); !ok {
				return false, fmt.Errorf("claim %s in DPoP has wrong type, got %T, want %T", key, expectedValue, expInt)
			} else if gotType != expInt {
				return false, fmt.Errorf("claim %s in DPoP has unexpected value, got %d, want %d", key, gotType, expInt)
			}
		default:
			return false, fmt.Errorf("claim %s in DPoP header has unexpected type, got %T", key, gotValue)
		}
	}
	return true, nil
}

// htuEquivalent compares two DPoP htu values after the syntax- and
// scheme-based URI normalization required by RFC 3986. The important
// difference from a raw string comparison is that a default port may be
// written explicitly or omitted.
func htuEquivalent(got, want string) bool {
	return canonicalizeHTU(got) == canonicalizeHTU(want)
}

// canonicalizeHTU normalizes a URI for DPoP htu comparison. Scheme and host
// names are case-insensitive, default ports are removed, and an empty path is
// treated as "/". If the value is not an absolute URI it is returned as-is so
// that malformed claims still fail closed against an exact comparison.
func canonicalizeHTU(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}

	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	switch {
	case port != "":
		u.Host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"): // IPv6 literal without a port
		u.Host = "[" + host + "]"
	default:
		u.Host = host
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}
