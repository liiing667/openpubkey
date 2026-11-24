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
	"encoding/json"
	"testing"
)

func TestSameIssuerAliases(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"https://accounts.google.com", "accounts.google.com", true},
		{"https://accounts.google.com", "https://accounts.google.com/", true},
		{"https://accounts.google.com", "https://accounts.google.com:443", true},
		{"https://EXAMPLE.com/tenant/", "https://example.com/tenant", true},
		{"https://example.com", "http://example.com", false},
		{"https://example.com/a", "https://example.com/b", false},
		{"https://example.com", "https://notexample.com", false},
		{"", "https://example.com", false},
	} {
		if got := SameIssuer(tc.a, tc.b); got != tc.same {
			t.Errorf("SameIssuer(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}
}

func TestOidcClaimsUnmarshalClearsPreviousResponse(t *testing.T) {
	var claims OidcClaims
	if err := json.Unmarshal([]byte(`{"iss":"https://a.example","sub":"alice","email":"alice@a","groups":["g1"]}`), &claims); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"sub":"bob"}`), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "" || claims.Email != "" || len(claims.Groups) != 0 || claims.Subject != "bob" {
		t.Fatalf("stale claims survived: %+v", claims)
	}
}
