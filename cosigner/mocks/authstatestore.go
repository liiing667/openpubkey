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

package mocks

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/openpubkey/openpubkey/cosigner"
	"github.com/openpubkey/openpubkey/pktoken"
)

// This is intended for testing purposes. The locking strategy used is not
// particularly efficient. Anyone building a Cosigner should use the interface
// above to replace this in-memory store with a database.
type AuthStateInMemoryStore struct {
	AuthIDIssuer     *cosigner.AuthIDIssuer
	AuthStateMap     map[string]*cosigner.AuthState
	AuthCodeMap      map[string]string
	AuthStateMapLock sync.RWMutex
	AuthcodeMapLock  sync.RWMutex
}

var _ cosigner.AuthcodeTransactionStore = (*AuthStateInMemoryStore)(nil)

func NewAuthStateInMemoryStore(hmacKey []byte) *AuthStateInMemoryStore {
	return &AuthStateInMemoryStore{
		AuthStateMap:     make(map[string]*cosigner.AuthState),
		AuthCodeMap:      make(map[string]string),
		AuthcodeMapLock:  sync.RWMutex{},
		AuthStateMapLock: sync.RWMutex{},
		AuthIDIssuer:     cosigner.NewAuthIDIssuer(hmacKey),
	}
}

// cloneAuthState copies the mutable parts of an AuthState so callers cannot
// mutate store state without going through the store.
func cloneAuthState(authState *cosigner.AuthState) cosigner.AuthState {
	if authState == nil {
		return cosigner.AuthState{}
	}
	cloned := *authState
	if authState.CosSignature != nil {
		cloned.CosSignature = append([]byte(nil), authState.CosSignature...)
	}
	return cloned
}

func (s *AuthStateInMemoryStore) LookupAuthState(authID string) (*cosigner.AuthState, bool) {
	s.AuthStateMapLock.RLock()
	authState, ok := s.AuthStateMap[authID]
	s.AuthStateMapLock.RUnlock()
	if !ok {
		return nil, false
	}
	cloned := cloneAuthState(authState)
	return &cloned, true
}

func (s *AuthStateInMemoryStore) UpdateAuthState(authID string, authState cosigner.AuthState) error {
	s.AuthStateMapLock.Lock()
	defer s.AuthStateMapLock.Unlock()

	if _, ok := s.AuthStateMap[authID]; !ok {
		return fmt.Errorf("failed to upload auth session because authID specified matches no session")
	} else {
		cloned := cloneAuthState(&authState)
		s.AuthStateMap[authID] = &cloned
		return nil
	}
}

func (s *AuthStateInMemoryStore) CreateNewAuthSession(pkt *pktoken.PKToken, ruri string, nonce string) (string, error) {
	var claims struct {
		Issuer string `json:"iss"`
		Aud    any    `json:"aud"`
		Sub    string `json:"sub"`
		Email  string `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return "", fmt.Errorf("failed to unmarshal PK Token: %w", err)
	}
	// An audience can be a string or an array of strings.
	//
	// RFC-7519 JSON Web Token (JWT) says:
	// "In the general case, the "aud" value is an array of case-
	// sensitive strings, each containing a StringOrURI value.  In the
	// special case when the JWT has one audience, the "aud" value MAY be a
	// single case-sensitive string containing a StringOrURI value."
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	var audience string
	switch t := claims.Aud.(type) {
	case string:
		audience = t
	case []any:
		audList := []string{}
		for _, v := range t {
			audList = append(audList, v.(string))
		}
		audience = strings.Join(audList, ",")
	default:
		return "", fmt.Errorf("failed to deserialize aud (audience) claim in ID Token: %T", t)
	}

	authState := &cosigner.AuthState{
		Pkt:              pkt,
		Issuer:           claims.Issuer,
		Aud:              audience,
		Sub:              claims.Sub,
		Username:         claims.Email,
		DisplayName:      strings.Split(claims.Email, "@")[0], //TODO: Use full name from ID Token
		RedirectURI:      ruri,
		Nonce:            nonce,
		AuthcodeRedeemed: false,
		AuthcodeIssued:   false,
	}

	if authID, err := s.AuthIDIssuer.CreateAuthID(uint64(time.Now().Unix())); err != nil {
		return "", err
	} else {
		s.AuthStateMapLock.Lock()
		defer s.AuthStateMapLock.Unlock()
		if _, ok := s.AuthStateMap[authID]; ok {
			return "", fmt.Errorf("specified authID is already in use")
		}
		s.AuthStateMap[authID] = authState
		return authID, nil
	}
}

func (s *AuthStateInMemoryStore) CreateAuthcode(authID string) (string, error) {
	authCodeBytes := make([]byte, 32)
	if _, err := rand.Read(authCodeBytes); err != nil {
		return "", err
	}
	authcode := hex.EncodeToString(authCodeBytes)

	// We take a full read write lock here to ensure we don't issue an authcode twice for the same session
	s.AuthStateMapLock.Lock()
	defer s.AuthStateMapLock.Unlock()

	if authState, ok := s.AuthStateMap[authID]; !ok {
		return "", fmt.Errorf("no such authID")
	} else if authState.AuthcodeIssued {
		return "", fmt.Errorf("authcode already issued for this authID")
	} else {
		s.AuthcodeMapLock.Lock()
		defer s.AuthcodeMapLock.Unlock()

		if _, ok := s.AuthCodeMap[authcode]; ok {
			return "", fmt.Errorf("authcode collision implies randomness failure in RNG")
		}
		authState.AuthcodeIssued = true
		s.AuthCodeMap[authcode] = authID

		return authcode, nil
	}
}

func (s *AuthStateInMemoryStore) RedeemAuthcode(authcode string) (cosigner.AuthState, string, error) {
	s.AuthStateMapLock.Lock()
	defer s.AuthStateMapLock.Unlock()
	s.AuthcodeMapLock.Lock()
	defer s.AuthcodeMapLock.Unlock()

	return s.redeemAuthcodeLocked(authcode)
}

// RedeemAuthcodeTx implements cosigner.AuthcodeTransactionStore. The callback
// and the commit both run while the store lock is held, so a failed callback
// leaves no trace and concurrent callers cannot both publish a cosignature.
func (s *AuthStateInMemoryStore) RedeemAuthcodeTx(
	authcode string,
	redeem func(authState cosigner.AuthState, authID string) ([]byte, error),
) ([]byte, error) {
	s.AuthStateMapLock.Lock()
	defer s.AuthStateMapLock.Unlock()
	s.AuthcodeMapLock.Lock()
	defer s.AuthcodeMapLock.Unlock()

	authState, authID, err := s.checkRedeemableAuthcodeLocked(authcode)
	if err != nil {
		return nil, err
	}

	cosSig, err := redeem(authState, authID)
	if err != nil {
		return nil, err
	}

	stored := s.AuthStateMap[authID]
	stored.AuthcodeRedeemed = true
	stored.CosSignature = append([]byte(nil), cosSig...)
	return append([]byte(nil), cosSig...), nil
}

// redeemAuthcodeLocked checks and consumes an authcode. The caller must hold
// both AuthStateMapLock and AuthcodeMapLock.
func (s *AuthStateInMemoryStore) redeemAuthcodeLocked(authcode string) (cosigner.AuthState, string, error) {
	authState, authID, err := s.checkRedeemableAuthcodeLocked(authcode)
	if err != nil {
		return cosigner.AuthState{}, "", err
	}

	stored := s.AuthStateMap[authID]
	stored.AuthcodeRedeemed = true
	stored.CosSignature = nil
	authState.AuthcodeRedeemed = true
	return authState, authID, nil
}

// checkRedeemableAuthcodeLocked verifies that an authcode has been issued and
// has not yet been consumed without mutating any state. The caller must hold
// both AuthStateMapLock and AuthcodeMapLock.
func (s *AuthStateInMemoryStore) checkRedeemableAuthcodeLocked(authcode string) (cosigner.AuthState, string, error) {
	authID, authcodeFound := s.AuthCodeMap[authcode]
	if !authcodeFound {
		return cosigner.AuthState{}, "", fmt.Errorf("invalid authcode")
	}

	authState := s.AuthStateMap[authID]
	if authState == nil {
		// This should never happen
		return cosigner.AuthState{}, "", fmt.Errorf("no auth session for this authcode")
	}
	if !authState.AuthcodeIssued {
		// This should never happen
		return cosigner.AuthState{}, "", fmt.Errorf("no authcode issued for this authID")
	}
	if authState.AuthcodeRedeemed {
		return cosigner.AuthState{}, "", fmt.Errorf("authcode has already been redeemed")
	}

	return cloneAuthState(authState), authID, nil
}
