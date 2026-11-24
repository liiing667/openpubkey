// Copyright 2025 OpenPubkey
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
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/stretchr/testify/require"
)

func newLoginGenerationTestOp(t *testing.T, redirectURIs []string) (*StandardOp, *mocks.MockOp) {
	t.Helper()

	clientID := "fake-client-id"
	issuer := googleIssuer
	opts := GetDefaultStandardOpOptions(issuer, clientID)
	opts.RedirectURIs = redirectURIs
	opts.OpenBrowser = false

	idp, err := mocks.NewMockOp(issuer, []mocks.Subject{{SubjectID: "alice@gmail.com"}})
	require.NoError(t, err)

	expSigningKey, expKeyID, expRecord := idp.RandomSigningKey()
	idp.MockProviderBackend.IDTokenTemplate = &mocks.IDTokenTemplate{
		CommitFunc: mocks.AddNonceCommit,
		Issuer:     issuer,
		Nonce:      "empty",
		Aud:        clientID,
		KeyID:      expKeyID,
		Alg:        expRecord.Alg,
		SigningKey: expSigningKey,
	}
	opts.HttpClient = idp.GetHTTPClient()

	op, ok := NewStandardOpWithOptions(opts).(*StandardOp)
	require.True(t, ok, "expected *StandardOp")
	return op, idp
}

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

func TestLoginGenerationInvalidation(t *testing.T) {
	op, ok := NewStandardOp("https://issuer.example.com", "client-id").(*StandardOp)
	require.True(t, ok, "expected *StandardOp")

	gen1 := op.beginLogin()
	require.True(t, op.loginActive(gen1))

	gen2 := op.beginLogin()
	require.False(t, op.loginActive(gen1), "starting a new login must invalidate the previous generation")
	require.True(t, op.loginActive(gen2))

	op.endLogin(gen1)
	require.True(t, op.loginActive(gen2), "ending a stale login must not invalidate the current generation")

	op.endLogin(gen2)
	require.False(t, op.loginActive(gen2), "ending the current login must invalidate its generation")
}

func TestCancelReleasesCallbackListener(t *testing.T) {
	// Use a single redirect URI so the re-login can only succeed if the
	// cancelled login released its listener.
	port := freeLoopbackPort(t)
	redirectURI := fmt.Sprintf("http://localhost:%d/login-callback", port)
	op, idp := newLoginGenerationTestOp(t, []string{redirectURI})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	op.SetLoginURIHook(func(uri string) error {
		cancel() // simulate the user cancelling the login
		return nil
	})
	_, err := op.RequestTokens(ctx, GenCIC(t))
	require.ErrorIs(t, err, context.Canceled)

	// The cancelled login must have released its listener: a new login can
	// rebind the same callback address and complete.
	userAuth := mocks.UserBrowserInteractionMock{SubjectId: "alice@gmail.com"}
	completeAuthentication := userAuth.BrowserOpenOverrideFunc(idp)
	var loginURI string
	op.SetLoginURIHook(func(uri string) error {
		loginURI = uri
		return completeAuthentication(uri)
	})
	tokens, err := op.RequestTokens(context.Background(), GenCIC(t))
	require.NoError(t, err)
	require.NotNil(t, tokens)
	require.Contains(t, loginURI, fmt.Sprintf(":%d/", port),
		"re-login should bind the same callback address released by the cancelled login")
}

func TestCancelReleasesCallbackListenerWithHTTPSessionHook(t *testing.T) {
	// Cosigner-style session hook: historically this kept the callback server
	// running after cancellation, leaking the listener and blocking re-login.
	port := freeLoopbackPort(t)
	redirectURI := fmt.Sprintf("http://localhost:%d/login-callback", port)
	op, idp := newLoginGenerationTestOp(t, []string{redirectURI})
	op.HookHTTPSession(func(w http.ResponseWriter, r *http.Request) {})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	op.SetLoginURIHook(func(uri string) error {
		cancel() // simulate the user cancelling the login
		return nil
	})
	_, err := op.RequestTokens(ctx, GenCIC(t))
	require.ErrorIs(t, err, context.Canceled)

	// Even with an HTTP session hook set, the cancelled login must have
	// released its listener so a new login can rebind and complete.
	userAuth := mocks.UserBrowserInteractionMock{SubjectId: "alice@gmail.com"}
	op.SetLoginURIHook(userAuth.BrowserOpenOverrideFunc(idp))
	tokens, err := op.RequestTokens(context.Background(), GenCIC(t))
	require.NoError(t, err)
	require.NotNil(t, tokens)
}

func TestStaleCallbackFromPreviousLoginRejected(t *testing.T) {
	redirectURIs := []string{
		fmt.Sprintf("http://localhost:%d/login-callback", freeLoopbackPort(t)),
		fmt.Sprintf("http://localhost:%d/login-callback", freeLoopbackPort(t)),
	}
	op, idp := newLoginGenerationTestOp(t, redirectURIs)

	// Login 1: capture its login URI but never complete the flow, leaving the
	// "browser tab" open on the OP's authorization page.
	loginURI1Ch := make(chan string, 1)
	op.SetLoginURIHook(func(uri string) error {
		loginURI1Ch <- uri
		return nil
	})
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	cic1 := GenCIC(t)
	login1Err := make(chan error, 1)
	go func() {
		_, err := op.RequestTokens(ctx1, cic1)
		login1Err <- err
	}()
	var uri1 string
	select {
	case uri1 = <-loginURI1Ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for login 1 to present its login URI")
	}

	// Login 2: starts a new login generation, invalidating login 1's
	// callback, and completes normally.
	userAuth2 := mocks.UserBrowserInteractionMock{SubjectId: "alice@gmail.com"}
	op.SetLoginURIHook(userAuth2.BrowserOpenOverrideFunc(idp))
	tokens2, err := op.RequestTokens(context.Background(), GenCIC(t))
	require.NoError(t, err)
	require.NotNil(t, tokens2)

	// The stale tab from login 1 now completes its flow. The callback belongs
	// to an old login generation and must not deliver tokens into login 1.
	staleAuth := mocks.UserBrowserInteractionMock{SubjectId: "alice@gmail.com"}
	require.NoError(t, staleAuth.BrowserOpenOverrideFunc(idp)(uri1))

	select {
	case err := <-login1Err:
		t.Fatalf("stale callback must not complete login 1, got: %v", err)
	default:
	}

	cancel1()
	select {
	case err := <-login1Err:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("login 1 did not return after cancellation")
	}
}
