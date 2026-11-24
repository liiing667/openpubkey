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

package verifier_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/stretchr/testify/require"
)

func newUserInfoRequesterForTest(t *testing.T, issuer, subject, accessToken string) *verifier.UserInfoRequester {
	t.Helper()
	requester, err := verifier.NewUserInfoRequester(&pktoken.PKToken{
		Payload: []byte(fmt.Sprintf(`{"iss":%q,"sub":%q}`, issuer, subject)),
	}, accessToken)
	require.NoError(t, err)
	return requester
}

func userInfoClient(issuer, token, response string) *http.Client {
	return mocks.NewMockUserInfoClient(
		issuer+"/.well-known/openid-configuration",
		issuer+"/userinfo",
		fmt.Sprintf(`{"issuer":%q,"userinfo_endpoint":%q}`, issuer, issuer+"/userinfo"),
		response,
		token,
	)
}

func TestUserInfoRequesterSwitchesIdentityWithoutLeakingOldResponse(t *testing.T) {
	requester := newUserInfoRequesterForTest(t, "https://a.example", "alice", "token-a")
	requester.HttpClient = userInfoClient("https://a.example", "token-a", `{"sub":"alice","email":"alice@a.example"}`)

	userInfoJSON, err := requester.Request(context.Background())
	require.NoError(t, err)
	require.Contains(t, userInfoJSON, `"sub":"alice"`)

	// Switch to another provider/user while reusing the requester. If the
	// provider answers with the previous user's JSON, it must be rejected
	// instead of being returned as the current result.
	requester.Issuer = "https://b.example"
	requester.Subject = "bob"
	requester.AccessToken = "token-b"
	requester.HttpClient = userInfoClient("https://b.example", "token-b", `{"sub":"alice","email":"alice@a.example"}`)

	userInfoJSON, err = requester.Request(context.Background())
	require.ErrorContains(t, err, "does not match")
	require.Empty(t, userInfoJSON)

	requester.HttpClient = userInfoClient("https://b.example", "token-b", `{"sub":"bob","email":"bob@b.example"}`)
	userInfoJSON, err = requester.Request(context.Background())
	require.NoError(t, err)
	require.Contains(t, userInfoJSON, `"sub":"bob"`)
	require.NotContains(t, userInfoJSON, "alice")
}

func TestUserInfoRequesterAcceptsIssuerAliases(t *testing.T) {
	requester := newUserInfoRequesterForTest(t, "https://accounts.google.com", "me", "token")
	requester.HttpClient = mocks.NewMockUserInfoClient(
		"https://accounts.google.com/.well-known/openid-configuration",
		"https://openidconnect.googleapis.com/v1/userinfo",
		`{"issuer":"accounts.google.com","userinfo_endpoint":"https://openidconnect.googleapis.com/v1/userinfo"}`,
		`{"iss":"accounts.google.com","sub":"me","name":"Alice Example"}`,
		"token",
	)

	userInfoJSON, err := requester.Request(context.Background())
	require.NoError(t, err)
	require.Contains(t, userInfoJSON, `"sub":"me"`)
	require.Contains(t, userInfoJSON, `"name":"Alice Example"`)
}

func TestUserInfoRequesterRequiresSubject(t *testing.T) {
	requester, err := verifier.NewUserInfoRequester(&pktoken.PKToken{
		Payload: []byte(`{"iss":"https://accounts.google.com"}`),
	}, "token")
	require.ErrorContains(t, err, "missing subject")
	require.Nil(t, requester)
}
