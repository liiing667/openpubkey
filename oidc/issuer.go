// Copyright 2026 OpenPubkey
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
	"net/url"
	"strings"
)

// SameIssuer reports whether two issuer identifiers refer to the same OpenID
// Provider. In addition to exact matches it accepts the harmless spelling
// aliases that occur in practice: a missing "https://" scheme (Google is known
// to emit both "accounts.google.com" and "https://accounts.google.com"), a
// trailing slash on the path, a default port, and different host casing.
//
// The comparison deliberately keeps the scheme, host, and path significant:
// "http://example.com" is not the same issuer as "https://example.com", and a
// different path is a different issuer.
func SameIssuer(a, b string) bool {
	normalizedA, okA := normalizeIssuer(a)
	normalizedB, okB := normalizeIssuer(b)
	return okA && okB && normalizedA == normalizedB
}

func normalizeIssuer(issuer string) (string, bool) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return "", false
	}

	// Some providers (notably Google) emit the issuer without a scheme. OIDC
	// discovery is always performed over HTTPS, so compare a missing scheme as
	// HTTPS rather than treating the value as an opaque string.
	if !strings.Contains(issuer, "://") {
		issuer = "https://" + issuer
	}

	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return "", false
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		// Issuer identifiers are URLs without query or fragment components.
		return "", false
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", false
	}

	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" {
		return "", false
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	path := strings.TrimRight(parsed.EscapedPath(), "/")
	return scheme + "://" + host + ":" + port + path, true
}
