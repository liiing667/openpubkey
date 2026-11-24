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

package choosers

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/providers"
	"github.com/stretchr/testify/require"
)

func TestChooseGenerationInvalidation(t *testing.T) {
	wc := NewWebChooser(nil, false)

	gen1 := wc.beginChoose()
	require.True(t, wc.chooseActive(gen1))

	gen2 := wc.beginChoose()
	require.False(t, wc.chooseActive(gen1), "starting a new chooser session must invalidate the previous generation")
	require.True(t, wc.chooseActive(gen2))

	wc.endChoose(gen1)
	require.True(t, wc.chooseActive(gen2), "ending a stale chooser session must not invalidate the current generation")

	wc.endChoose(gen2)
	require.False(t, wc.chooseActive(gen2), "ending the current chooser session must invalidate its generation")
}

// triggerRedirect keeps firing the OP's browser window hook until the
// selection handler has installed it and consumes the redirect URI.
func triggerRedirect(t *testing.T, op providers.BrowserOpenIdProvider, redirectURI string) {
	t.Helper()
	standardOp, ok := op.(*providers.StandardOp)
	require.True(t, ok, "expected *providers.StandardOp")
	require.Eventually(t, func() bool {
		done := make(chan struct{})
		go func() {
			standardOp.TriggerBrowserWindowHook(redirectURI)
			close(done)
		}()
		select {
		case <-done:
			return true
		case <-time.After(20 * time.Millisecond):
			return false
		}
	}, 5*time.Second, 50*time.Millisecond, "redirect was not consumed by the selection handler")
}

func TestChooseOpCancelReleasesListenerAndAllowsRetry(t *testing.T) {
	googleOp := providers.NewGoogleOpWithOptions(providers.GetDefaultGoogleOpOptions())
	webChooser := NewWebChooser([]providers.BrowserOpenIdProvider{googleOp}, false)

	uriCh := make(chan string, 1)
	webChooser.SetLoginURIHook(func(uri string) error {
		uriCh <- uri
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	type chooseResult struct {
		op  providers.OpenIdProvider
		err error
	}
	chooseResultCh := make(chan chooseResult, 1)
	go func() {
		op, err := webChooser.ChooseOp(ctx)
		chooseResultCh <- chooseResult{op: op, err: err}
	}()

	var uri string
	select {
	case uri = <-uriCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the chooser URI")
	}
	cancel()
	select {
	case result := <-chooseResultCh:
		require.ErrorIs(t, result.err, context.Canceled)
		require.Nil(t, result.op)
	case <-time.After(5 * time.Second):
		t.Fatal("ChooseOp did not return after cancellation")
	}

	// The cancelled chooser must have released its listener.
	parsed, err := url.Parse(uri)
	require.NoError(t, err)
	host := parsed.Hostname()
	if host == "localhost" {
		host = "127.0.0.1"
	}
	require.Eventually(t, func() bool {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, parsed.Port()))
		if err != nil {
			return false
		}
		_ = ln.Close()
		return true
	}, 3*time.Second, 10*time.Millisecond, "cancelled chooser should release its listener")

	// A new chooser session can start after the cancellation and complete.
	gotRedirect := false
	redirectServer, redirectURI := CreateServerToHandleRedirect(t, &gotRedirect)
	defer redirectServer.Close()

	uriCh2 := make(chan string, 1)
	webChooser.SetLoginURIHook(func(uri string) error {
		uriCh2 <- uri
		return nil
	})
	chooseResultCh2 := make(chan chooseResult, 1)
	go func() {
		op, err := webChooser.ChooseOp(context.Background())
		chooseResultCh2 <- chooseResult{op: op, err: err}
	}()

	var uri2 string
	select {
	case uri2 = <-uriCh2:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the chooser URI after retry")
	}
	parsed2, err := url.Parse(uri2)
	require.NoError(t, err)

	// Load the chooser page and select the provider.
	resp, err := http.Get(uri2)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	selectRespCh := make(chan *http.Response, 1)
	go func() {
		resp, err := http.Get(fmt.Sprintf("http://%s/select?op=google", parsed2.Host))
		if err == nil {
			selectRespCh <- resp
		}
	}()

	select {
	case result := <-chooseResultCh2:
		require.NoError(t, result.err)
		require.NotNil(t, result.op)
	case <-time.After(5 * time.Second):
		t.Fatal("ChooseOp did not return the selected provider after retry")
	}

	// Complete the redirect handoff to the OP login.
	triggerRedirect(t, googleOp, redirectURI)

	select {
	case resp := <-selectRespCh:
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	case <-time.After(5 * time.Second):
		t.Fatal("selection did not complete its redirect after retry")
	}
	require.Eventually(t, func() bool { return gotRedirect }, 3*time.Second, 10*time.Millisecond)
}

func TestDuplicateSelectionRejected(t *testing.T) {
	googleOp := providers.NewGoogleOpWithOptions(providers.GetDefaultGoogleOpOptions())
	webChooser := WebChooser{
		OpList:        []providers.BrowserOpenIdProvider{googleOp},
		OpenBrowser:   false,
		useMockServer: true,
	}

	gotRedirect := false
	redirectServer, redirectURI := CreateServerToHandleRedirect(t, &gotRedirect)
	defer redirectServer.Close()

	type chooseResult struct {
		op  providers.OpenIdProvider
		err error
	}
	chooseResultCh := make(chan chooseResult, 1)
	go func() {
		op, err := webChooser.ChooseOp(context.Background())
		chooseResultCh <- chooseResult{op: op, err: err}
	}()

	require.Eventually(t, func() bool {
		return webChooser.mockServer != nil && webChooser.mockServer.URL != ""
	}, 3*time.Second, 10*time.Millisecond)

	selectURL := webChooser.mockServer.URL + "/select?op=google"
	firstRespCh := make(chan *http.Response, 1)
	go func() {
		resp, err := http.Get(selectURL)
		if err == nil {
			firstRespCh <- resp
		}
	}()

	select {
	case result := <-chooseResultCh:
		require.NoError(t, result.err)
		require.NotNil(t, result.op)
	case <-time.After(5 * time.Second):
		t.Fatal("ChooseOp did not return the selected provider")
	}

	// The chooser session has ended: a duplicate navigation to the selection
	// endpoint must be rejected rather than queuing a second provider choice.
	resp, err := http.Get(selectURL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusGone, resp.StatusCode)

	// Let the in-flight selection finish its redirect handoff.
	triggerRedirect(t, googleOp, redirectURI)

	select {
	case resp := <-firstRespCh:
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	case <-time.After(5 * time.Second):
		t.Fatal("first selection did not complete its redirect")
	}
	require.Eventually(t, func() bool { return gotRedirect }, 3*time.Second, 10*time.Millisecond)
}
