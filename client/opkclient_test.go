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

package client_test

import (
	"context"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/choosers"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/internal/jwx"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	clientID := "test-client-id"

	testCases := []struct {
		name        string
		gq          bool
		signer      bool
		signerAlg   jose.KeyAlgorithm
		extraClaims map[string]string
	}{
		{name: "without GQ", gq: false, signer: false},
		{name: "with GQ", gq: true, signer: false},
		{name: "with GQ, with signer", gq: true, signer: true, signerAlg: jose.RS256},
		{name: "with GQ, with signer, with empty extraClaims", gq: true, signer: true, signerAlg: jose.ES256, extraClaims: map[string]string{}},
		{name: "with GQ, with signer, with extraClaims", gq: true, signer: true, signerAlg: jose.ES256, extraClaims: map[string]string{"extra": "yes"}},
		{name: "with GQ, with extraClaims", gq: true, signer: false, extraClaims: map[string]string{"extra": "yes", "aaa": "bbb"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			googleOpOpts := providers.GetDefaultGoogleOpOptions()
			googleOpOpts.Issuer = "mockIssuer"
			googleOpOpts.ClientID = clientID
			googleOpOpts.GQSign = tc.gq

			op, err := providers.CreateMockGoogleOpWithOpts(googleOpOpts,
				mocks.UserBrowserInteractionMock{
					SubjectId: "alice@gmail.com",
				})
			require.NoError(t, err, tc.name)

			var c *client.OpkClient
			if tc.signer {
				signer, err := util.GenKeyPair(tc.signerAlg)
				require.NoError(t, err, tc.name)
				c, err = client.New(op, client.WithSigner(signer, tc.signerAlg))
				require.NoError(t, err, tc.name)
				require.Equal(t, signer, c.GetSigner(), tc.name)
				require.Equal(t, tc.signerAlg, c.GetAlg(), tc.name)
			} else {
				c, err = client.New(op)
				require.NoError(t, err, tc.name)
			}

			var pkt *pktoken.PKToken
			if tc.extraClaims != nil {
				extraClaimsOpts := []client.AuthOpts{}
				for k, v := range tc.extraClaims {
					extraClaimsOpts = append(extraClaimsOpts,
						client.WithExtraClaim(k, v))
				}

				pkt, err = c.Auth(context.Background(), extraClaimsOpts...)
				require.NoError(t, err, tc.name)

				cicPH, err := jwx.HeadersAsMap(pkt.Cic.ProtectedHeaders())
				require.NoError(t, err, tc.name)

				for k, v := range tc.extraClaims {
					require.Equal(t, v, cicPH[k], tc.name)
				}
			} else {
				pkt, err = c.Auth(context.Background())
				require.NoError(t, err, tc.name)
			}

			providerAlg, ok := pkt.ProviderAlgorithm()
			require.True(t, ok, "missing algorithm", tc.name)

			cic, err := pkt.GetCicValues()
			require.NoError(t, err)
			err = op.VerifyIDToken(context.Background(), pkt.OpToken, cic)
			require.NoError(t, err, tc.name)

			require.True(t, c.HasRefreshToken())
			pktRefreshed, err := c.Refresh(context.Background())
			require.NoError(t, err)
			require.NotNil(t, pktRefreshed)

			if tc.gq {
				require.Equal(t, jose.GQ256, providerAlg, tc.name)

				// Verify our GQ signature
				opPubKey, err := op.PublicKeyByToken(context.Background(), pkt.OpToken)
				require.NoError(t, err, tc.name)

				rsaKey, ok := opPubKey.PublicKey.(*rsa.PublicKey)
				require.Equal(t, true, ok)

				ok, err = gq.GQ256VerifyJWT(rsaKey, pkt.OpToken)
				require.NoError(t, err, tc.name)
				require.True(t, ok, "error verifying OP GQ signature on PK Token (ID Token invalid)")
			} else {
				// Expect alg to be RS256 alg when not signing with GQ
				require.Equal(t, jose.RS256, providerAlg, tc.name)
			}
		})
	}
}

func TestClientWithWebChooser(t *testing.T) {
	googleOpOpts := providers.GetDefaultGoogleOpOptions()

	googleOp, err := providers.CreateMockGoogleOpWithOpts(googleOpOpts,
		mocks.UserBrowserInteractionMock{
			SubjectId: "alice@gmail.com",
		})
	require.NoError(t, err)

	azureOpOpts := providers.GetDefaultAzureOpOptions()
	azureOp, err := providers.CreateMockAzureOpWithOpts(azureOpOpts,
		mocks.UserBrowserInteractionMock{
			SubjectId: "alice@hotmail.com",
		})
	require.NoError(t, err)

	gitlabOpOpts := providers.GetDefaultGitlabOpOptions()
	gitlabOp, err := providers.CreateMockGitlabOpWithOpts(gitlabOpOpts,
		mocks.UserBrowserInteractionMock{
			SubjectId: "alice@gmail.com",
		})
	require.NoError(t, err)

	helloOpOpts := providers.GetDefaultHelloOpOptions()
	helloOp, err := providers.CreateMockHelloOpWithOpts(helloOpOpts,
		mocks.UserBrowserInteractionMock{
			SubjectId: "alice@gmail.com",
		})
	require.NoError(t, err)

	opToChoose := "gitlab"
	chooser := choosers.NewMockWebChooser(
		[]providers.BrowserOpenIdProvider{
			googleOp.(providers.BrowserOpenIdProvider),
			azureOp.(providers.BrowserOpenIdProvider),
			gitlabOp.(providers.BrowserOpenIdProvider),
			helloOp,
		},
		opToChoose,
	)
	op, err := chooser.ChooseOp(context.Background())
	require.NoError(t, err)

	c, err := client.New(op)
	require.NoError(t, err)

	pkt, err := c.Auth(context.Background())
	require.NoError(t, err)

	providerAlg, ok := pkt.ProviderAlgorithm()
	require.True(t, ok, "missing algorithm")

	require.Equal(t, jose.RS256, providerAlg)

	cic, err := pkt.GetCicValues()
	require.NoError(t, err)
	err = op.VerifyIDToken(context.Background(), pkt.OpToken, cic)
	require.NoError(t, err)

	pktRefreshed, err := c.Refresh(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pktRefreshed)
}

func TestClientRefreshErrorHandling(t *testing.T) {
	signerAlg := jose.ES256

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, _, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	signer, err := util.GenKeyPair(signerAlg)
	require.NoError(t, err)
	c, err := client.New(op, client.WithSigner(signer, signerAlg))
	require.NoError(t, err)

	_, err = c.Refresh(context.Background())
	require.ErrorContains(t, err, "no refresh token set")

	// Now that we have called Auth refresh should work
	pkt1, err := c.Auth(context.Background())
	require.NoError(t, err)
	pkt1Com, err := pkt1.Compact()
	require.NoError(t, err)

	pkt2, err := c.Refresh(context.Background())
	require.NoError(t, err)

	pkt2Com, err := pkt2.Compact()
	require.NoError(t, err)
	require.NotEqual(t, string(pkt1Com), string(pkt2Com))

	pkt3, err := c.GetPKToken()
	require.NoError(t, err)
	pkt3com, err := pkt3.Compact()
	require.NoError(t, err)
	require.Equal(t, pkt2Com, pkt3com)

	// Nil out PK Token in client so check we catch the error of a nil PK Token
	c.SetPKToken(nil)
	_, err = c.Refresh(context.Background())
	require.ErrorContains(t, err, "no PK Token set, run Auth() to create a PK Token first")
}

func TestClientRefreshNotSupported(t *testing.T) {
	signerAlg := jose.ES256

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, _, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	// Removes RefreshTokens from Op so we can test that client
	// handles Op's that can't refresh tokens
	opRefreshUnsupported := providers.NewNonRefreshableOp(op)

	signer, err := util.GenKeyPair(signerAlg)
	require.NoError(t, err)
	c, err := client.New(opRefreshUnsupported, client.WithSigner(signer, signerAlg))
	require.NoError(t, err)

	pkt, err := c.Auth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pkt)

	_, err = c.Refresh(context.Background())
	require.ErrorContains(t, err, "does not support OIDC refresh requests")
}

// errRefreshOp wraps a MockProvider and fails refresh requests while err is set.
type errRefreshOp struct {
	*providers.MockProvider
	err error
}

func (e *errRefreshOp) RefreshTokens(ctx context.Context, refreshToken []byte) (*oidc.Tokens, error) {
	if e.err != nil {
		return nil, e.err
	}
	return e.MockProvider.RefreshTokens(ctx, refreshToken)
}

func TestClientRefreshFailurePreservesState(t *testing.T) {
	signerAlg := jose.ES256

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, _, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)
	failOp := &errRefreshOp{MockProvider: op}

	signer, err := util.GenKeyPair(signerAlg)
	require.NoError(t, err)
	c, err := client.New(failOp, client.WithSigner(signer, signerAlg))
	require.NoError(t, err)

	_, err = c.Auth(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(0), c.GetGeneration())

	// A successful refresh to establish a fresh ID Token
	pkt2, err := c.Refresh(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pkt2.FreshIDToken)
	require.Equal(t, uint64(1), c.GetGeneration())

	// When the refresh fails the client must keep its previous state:
	// the caller keeps the previous fresh ID Token and can continue to use
	// it as their session.
	failOp.err = errors.New("OP unreachable")
	_, err = c.Refresh(context.Background())
	require.ErrorContains(t, err, "OP unreachable")

	pktAfter, err := c.GetPKToken()
	require.NoError(t, err)
	require.Equal(t, pkt2.FreshIDToken, pktAfter.FreshIDToken,
		"failed refresh must not clear or overwrite the previous fresh ID Token")
	require.Equal(t, uint64(1), c.GetGeneration(),
		"failed refresh must not bump the session generation")
	require.True(t, c.HasRefreshToken(),
		"failed refresh must not drop the refresh token")

	// Once the OP is reachable again the same session can be refreshed
	failOp.err = nil
	pkt3, err := c.Refresh(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pkt3.FreshIDToken)
	require.Equal(t, uint64(2), c.GetGeneration())
}

// wrongSubjectRefreshOp wraps a MockProvider and returns a refreshed ID Token
// issued for a different subject than the original ID Token.
type wrongSubjectRefreshOp struct {
	*providers.MockProvider
	template *mocks.IDTokenTemplate
}

func (w *wrongSubjectRefreshOp) RefreshTokens(_ context.Context, _ []byte) (*oidc.Tokens, error) {
	return w.template.IssueTokensWithSubject(&mocks.Subject{SubjectID: "mallory"})
}

func TestClientRefreshVerifiesSubjectBeforeCommit(t *testing.T) {
	signerAlg := jose.ES256

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, idtTemplate, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)
	evilOp := &wrongSubjectRefreshOp{MockProvider: op, template: idtTemplate}

	signer, err := util.GenKeyPair(signerAlg)
	require.NoError(t, err)
	c, err := client.New(evilOp, client.WithSigner(signer, signerAlg))
	require.NoError(t, err)

	pkt1, err := c.Auth(context.Background())
	require.NoError(t, err)
	require.Nil(t, pkt1.FreshIDToken)

	// The refreshed ID Token is for a different subject; the client must
	// reject it and keep its previous state untouched.
	_, err = c.Refresh(context.Background())
	require.ErrorContains(t, err, "error verifying refreshed ID Token")

	pktAfter, err := c.GetPKToken()
	require.NoError(t, err)
	require.Nil(t, pktAfter.FreshIDToken,
		"rejected refreshed ID Token must not be committed")
	require.Equal(t, uint64(0), c.GetGeneration())
	require.True(t, c.HasRefreshToken())
}

// nonRotatingRefreshOp wraps a MockProvider and does not return a refresh
// token on refresh, like OPs (e.g. Google) that do not rotate refresh tokens.
type nonRotatingRefreshOp struct {
	*providers.MockProvider
}

func (n *nonRotatingRefreshOp) RefreshTokens(ctx context.Context, refreshToken []byte) (*oidc.Tokens, error) {
	tokens, err := n.MockProvider.RefreshTokens(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	return &oidc.Tokens{
		IDToken:     tokens.IDToken,
		AccessToken: tokens.AccessToken,
	}, nil
}

func TestClientRefreshKeepsRefreshTokenWhenNotRotated(t *testing.T) {
	signerAlg := jose.ES256

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, _, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)
	nonRotatingOp := &nonRotatingRefreshOp{MockProvider: op}

	signer, err := util.GenKeyPair(signerAlg)
	require.NoError(t, err)
	c, err := client.New(nonRotatingOp, client.WithSigner(signer, signerAlg))
	require.NoError(t, err)

	_, err = c.Auth(context.Background())
	require.NoError(t, err)
	require.True(t, c.HasRefreshToken())

	// Both refreshes must succeed even though the OP never returns a new
	// refresh token: the client keeps using the one it already holds.
	for i := uint64(1); i <= 2; i++ {
		pkt, err := c.Refresh(context.Background())
		require.NoError(t, err)
		require.NotNil(t, pkt.FreshIDToken)
		require.Equal(t, i, c.GetGeneration())
		require.True(t, c.HasRefreshToken(),
			"client must keep its refresh token when the OP does not rotate it")
	}
}

// serializedRefreshOp wraps a MockProvider and serializes RefreshTokens so
// the mock backend (which is not concurrency-safe) is not raced; the test
// exercises the client's own concurrency handling.
type serializedRefreshOp struct {
	*providers.MockProvider
	mu sync.Mutex
}

func (s *serializedRefreshOp) RefreshTokens(ctx context.Context, refreshToken []byte) (*oidc.Tokens, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.MockProvider.RefreshTokens(ctx, refreshToken)
}

func TestClientRefreshConcurrent(t *testing.T) {
	signerAlg := jose.ES256

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, _, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)
	serializedOp := &serializedRefreshOp{MockProvider: op}

	signer, err := util.GenKeyPair(signerAlg)
	require.NoError(t, err)
	c, err := client.New(serializedOp, client.WithSigner(signer, signerAlg))
	require.NoError(t, err)

	_, err = c.Auth(context.Background())
	require.NoError(t, err)

	const numRefreshes = 8
	var wg sync.WaitGroup
	errs := make(chan error, numRefreshes)
	for range numRefreshes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pkt, err := c.Refresh(context.Background())
			if err != nil {
				errs <- err
				return
			}
			if pkt.FreshIDToken == nil {
				errs <- errors.New("refreshed PK Token missing fresh ID Token")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	// Every concurrent refresh must have committed exactly once; none may
	// have overwritten another one's commit.
	require.Equal(t, uint64(numRefreshes), c.GetGeneration())
	pkt, err := c.GetPKToken()
	require.NoError(t, err)
	require.NotNil(t, pkt.FreshIDToken)
	require.True(t, c.HasRefreshToken())
}

func TestKeybinding(t *testing.T) {
	helloOpOpts := providers.GetDefaultHelloOpOptions()
	op, err := providers.CreateMockHelloKeyBindingOpWithOpts(helloOpOpts,
		mocks.UserBrowserInteractionMock{
			SubjectId: "alice@gmail.com",
		})

	require.NoError(t, err)
	require.NotNil(t, op)
	c, err := client.New(op)
	require.NoError(t, err)
	pkt, err := c.Auth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pkt)

	idt, err := oidc.NewJwt(pkt.OpToken)
	require.NoError(t, err)

	require.NotNil(t, idt.GetClaims().Cnf, "expected cnf claim in key-bound ID token")
	require.Len(t, idt.GetClaims().Cnf.Jwk, 5, "expected jwk in cnf claim of key-bound ID token")

	cic, err := pkt.GetCicValues()
	require.NoError(t, err)

	err = c.Op.VerifyIDToken(context.Background(), pkt.OpToken, cic)
	require.NoError(t, err)
}

func TestKeybindingRefresh(t *testing.T) {
	helloOpOpts := providers.GetDefaultHelloOpOptions()
	op, err := providers.CreateMockHelloKeyBindingOpWithOpts(helloOpOpts,
		mocks.UserBrowserInteractionMock{
			SubjectId: "alice@gmail.com",
		})
	require.NoError(t, err)
	require.NotNil(t, op)

	c, err := client.New(op)
	require.NoError(t, err)

	pkt, err := c.Auth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pkt)

	// The refreshable OP is what we are exercising: RefreshTokens issues a new
	// key-bound ID Token and VerifyRefreshedIDToken checks it against the
	// original (same subject, not older, same cnf key binding, OP signature).
	refreshableOp, ok := c.Op.(providers.RefreshableOpenIdProvider)
	require.True(t, ok, "key-bound Hello OP should be refreshable")

	pktRefreshed, err := c.Refresh(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pktRefreshed)
	require.NotNil(t, pktRefreshed.FreshIDToken, "refreshed PK Token should carry a fresh ID Token")

	// Positive case: the freshly refreshed ID Token verifies against the original.
	err = refreshableOp.VerifyRefreshedIDToken(context.Background(), pkt.OpToken, pktRefreshed.FreshIDToken)
	require.NoError(t, err)

	// The refreshed ID Token must still carry a cnf key binding.
	reIdt, err := oidc.NewJwt(pktRefreshed.FreshIDToken)
	require.NoError(t, err)
	require.NotNil(t, reIdt.GetClaims().Cnf, "expected cnf claim in refreshed key-bound ID token")

	// Negative case: swapping the arguments must fail RequireOlder, since the
	// refreshed token is not older than the original.
	err = refreshableOp.VerifyRefreshedIDToken(context.Background(), pktRefreshed.FreshIDToken, pkt.OpToken)
	require.Error(t, err)
}

func TestKeybindingDeviceFlow(t *testing.T) {
	helloOpOpts := providers.GetDefaultHelloOpOptions()
	helloOpOpts.DeviceFlow = true
	op, err := providers.CreateMockHelloKeyBindingOpWithOpts(helloOpOpts,
		mocks.UserBrowserInteractionMock{
			SubjectId: "alice@gmail.com",
		})

	require.NoError(t, err)
	require.NotNil(t, op)
	c, err := client.New(op)
	require.NoError(t, err)
	pkt, err := c.Auth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pkt)

	idt, err := oidc.NewJwt(pkt.OpToken)
	require.NoError(t, err)

	require.NotNil(t, idt.GetClaims().Cnf, "expected cnf claim in key-bound ID token")
	require.Len(t, idt.GetClaims().Cnf.Jwk, 5, "expected jwk in cnf claim of key-bound ID token")

	cic, err := pkt.GetCicValues()
	require.NoError(t, err)

	err = c.Op.VerifyIDToken(context.Background(), pkt.OpToken, cic)
	require.NoError(t, err)
}

func TestDeviceFlow(t *testing.T) {
	helloOpOpts := providers.GetDefaultHelloOpOptions()
	helloOpOpts.DeviceFlow = true
	op, err := providers.CreateMockHelloOpWithOpts(helloOpOpts,
		mocks.UserBrowserInteractionMock{
			SubjectId: "alice@gmail.com",
		})
	require.NoError(t, err)
	require.NotNil(t, op)
	c, err := client.New(op)
	require.NoError(t, err)
	pkt, err := c.Auth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pkt)

	cic, err := pkt.GetCicValues()
	require.NoError(t, err)

	err = c.Op.VerifyIDToken(context.Background(), pkt.OpToken, cic)
	require.NoError(t, err)
}
