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

package cosigner

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/cosigner/msgs"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/pktoken"
)

type AuthCosigner struct {
	Cosigner
	Issuer         string
	KeyID          string
	AuthStateStore AuthStateStore
}

func New(signer crypto.Signer, alg jose.KeyAlgorithm, issuer, keyID string, store AuthStateStore) (*AuthCosigner, error) {
	return &AuthCosigner{
		Cosigner: Cosigner{
			Alg:    alg,
			Signer: signer},
		Issuer:         issuer,
		KeyID:          keyID,
		AuthStateStore: store,
	}, nil
}

func (c *AuthCosigner) InitAuth(pkt *pktoken.PKToken, sig []byte) (string, error) {
	msg, err := pkt.VerifySignedMessage(sig)
	if err != nil {
		return "", fmt.Errorf("failed to verify sig: %w", err)
	}
	var initMFAAuth *msgs.InitMFAAuth
	if err := json.Unmarshal(msg, &initMFAAuth); err != nil {
		return "", fmt.Errorf("failed to parse InitMFAAuth message: %w", err)
	} else if initMFAAuth.Issuer != c.Issuer {
		return "", fmt.Errorf("signed message is for wrong cosigner, got issuer=(%s), expected issuer=(%s)", initMFAAuth.Issuer, c.Issuer)
	} else if time.Since(time.Unix(initMFAAuth.TimeSigned, 0)).Minutes() > 2 {
		return "", fmt.Errorf("timestamp (%d) in InitMFAAuth message too old, current time is (%d)", initMFAAuth.TimeSigned, time.Now().Unix())
	} else if time.Until(time.Unix(initMFAAuth.TimeSigned, 0)).Minutes() > 2 {
		return "", fmt.Errorf("timestamp (%d) in InitMFAAuth message too far in the future, current time is (%d)", initMFAAuth.TimeSigned, time.Now().Unix())
	} else if authID, err := c.AuthStateStore.CreateNewAuthSession(pkt, initMFAAuth.RedirectUri, initMFAAuth.Nonce); err != nil {
		return "", err
	} else {
		return authID, nil
	}
}

func (c *AuthCosigner) NewAuthcode(authID string) (string, error) {
	return c.AuthStateStore.CreateAuthcode(authID)
}

func (c *AuthCosigner) RedeemAuthcode(sig []byte) ([]byte, error) {
	msg, err := jws.Parse(sig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse sig: %w", err)
	}
	authcode := string(msg.Payload())

	// Verification, identity binding, consumption of the authcode and
	// publication of the cosignature all happen in this callback. The store
	// runs it in a transaction: an invalid signature or a signing failure
	// leaves the authcode available, while a successful call commits both the
	// consumed flag and the cosignature at once.
	redeem := func(authState AuthState, authID string) ([]byte, error) {
		pkt := authState.Pkt
		if pkt == nil {
			return nil, fmt.Errorf("auth session has no PK Token")
		}
		if _, err := pkt.VerifySignedMessage(sig); err != nil {
			return nil, fmt.Errorf("error verifying sig: %w", err)
		}
		return c.IssueSignature(pkt, authState, authID)
	}

	if txStore, ok := c.AuthStateStore.(AuthcodeTransactionStore); ok {
		return txStore.RedeemAuthcodeTx(authcode, redeem)
	}

	// Preserve compatibility with stores that only implement the original
	// interface. RedeemAuthcode consumes the authcode before we get a chance
	// to verify the signature, so roll it back if verification or signing
	// fails. Stores should implement AuthcodeTransactionStore to make this
	// atomic and to survive a crash.
	authState, authID, err := c.AuthStateStore.RedeemAuthcode(authcode)
	if err != nil {
		return nil, err
	}
	cosSig, err := redeem(authState, authID)
	if err != nil {
		authState.AuthcodeRedeemed = false
		authState.CosSignature = nil
		if updateErr := c.AuthStateStore.UpdateAuthState(authID, authState); updateErr != nil {
			return nil, fmt.Errorf("%w (failed to roll back authcode consumption: %v)", err, updateErr)
		}
		return nil, err
	}
	return cosSig, nil
}

func (c *AuthCosigner) IssueSignature(pkt *pktoken.PKToken, authState AuthState, authID string) ([]byte, error) {

	protected := pktoken.CosignerClaims{
		Issuer:      c.Issuer,
		KeyID:       c.KeyID,
		Algorithm:   c.Alg,
		AuthID:      authID,
		AuthTime:    time.Now().Unix(),
		IssuedAt:    time.Now().Unix(),
		Expiration:  time.Now().Add(time.Hour).Unix(),
		RedirectURI: authState.RedirectURI,
		Nonce:       authState.Nonce,
		Typ:         string(pktoken.COS),
	}

	// Now that our mfa has authenticated the user, we can add our signature
	return c.Cosign(pkt, protected)
}
