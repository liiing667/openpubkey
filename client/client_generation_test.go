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

package client

import (
	"context"
	"sync"
	"testing"

	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/stretchr/testify/require"
)

func TestStaleAuthGenerationCannotCommit(t *testing.T) {
	mockOp, _, _, err := providers.NewMockProvider(providers.DefaultMockProviderOpts())
	require.NoError(t, err)
	c, err := New(mockOp)
	require.NoError(t, err)

	pkt, err := c.Auth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pkt)
	require.True(t, c.HasRefreshToken())

	// A completion from an older login generation must not overwrite the
	// identity committed by a newer one.
	staleGen := c.beginAuth()
	currentGen := c.beginAuth()

	_, err = c.commitAuth(staleGen, pkt, &simpleoidc.Tokens{
		RefreshToken: []byte("stale-refresh-token"),
		AccessToken:  []byte("stale-access-token"),
	})
	require.ErrorContains(t, err, "stale login attempt")
	require.NotEqual(t, []byte("stale-refresh-token"), c.refreshToken)
	require.NotEqual(t, []byte("stale-access-token"), c.accessToken)

	_, err = c.commitAuth(currentGen, pkt, &simpleoidc.Tokens{
		RefreshToken: []byte("fresh-refresh-token"),
		AccessToken:  []byte("fresh-access-token"),
	})
	require.NoError(t, err)
	require.Equal(t, []byte("fresh-refresh-token"), c.refreshToken)
	require.Equal(t, []byte("fresh-access-token"), c.accessToken)
}

// gateOp blocks the first RequestTokens call until a second one arrives,
// forcing two concurrent Auth calls to overlap their login generations.
type gateOp struct {
	providers.OpenIdProvider
	mu         sync.Mutex
	calls      int
	secondCall chan struct{}
	// callMu serializes the delegated RequestTokens calls: the mock provider
	// backend keeps mutable per-request state and is not safe for concurrent
	// use. The login generations already overlap by the time the gate opens,
	// so serializing here does not affect what is being tested.
	callMu sync.Mutex
}

func (g *gateOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	g.mu.Lock()
	g.calls++
	call := g.calls
	if g.calls == 2 {
		close(g.secondCall)
	}
	g.mu.Unlock()
	if call == 1 {
		select {
		case <-g.secondCall:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	g.callMu.Lock()
	defer g.callMu.Unlock()
	return g.OpenIdProvider.RequestTokens(ctx, cic)
}

func TestConcurrentAuthOnlyLatestGenerationCommits(t *testing.T) {
	mockOp, _, _, err := providers.NewMockProvider(providers.DefaultMockProviderOpts())
	require.NoError(t, err)
	op := &gateOp{OpenIdProvider: mockOp, secondCall: make(chan struct{})}

	c, err := New(op)
	require.NoError(t, err)

	type authResult struct {
		pkt *pktoken.PKToken
		err error
	}
	results := make(chan authResult, 2)
	for i := 0; i < 2; i++ {
		go func() {
			pkt, err := c.Auth(context.Background())
			results <- authResult{pkt: pkt, err: err}
		}()
	}

	// Exactly one Auth may commit its identity; the stale login generation
	// is discarded and must not overwrite the client's PK Token.
	var winner *pktoken.PKToken
	staleErrs := 0
	for i := 0; i < 2; i++ {
		result := <-results
		if result.err == nil {
			require.Nil(t, winner, "only one Auth may commit its identity")
			winner = result.pkt
		} else {
			require.ErrorContains(t, result.err, "stale login attempt")
			require.Nil(t, result.pkt)
			staleErrs++
		}
	}
	require.Equal(t, 1, staleErrs)
	require.NotNil(t, winner)

	current, err := c.GetPKToken()
	require.NoError(t, err)
	winnerCompact, err := winner.Compact()
	require.NoError(t, err)
	currentCompact, err := current.Compact()
	require.NoError(t, err)
	require.Equal(t, string(winnerCompact), string(currentCompact),
		"the client's PK Token must be the one committed by the latest login generation")
}
