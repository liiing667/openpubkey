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

package gq

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/util"
)

// Verify verifies a GQ1 signature over a message, using the public identity of the signer.
//
// Comments throughout refer to stages as specified in the ISO/IEC 14888-2 standard.
// A nil error means the proof was accepted; otherwise the error records the
// stage at which verification failed so callers can distinguish a malformed
// proof, an out-of-range witness, or a failed equality check instead of
// receiving an indistinguishable false.
func (sv *signerVerifier) Verify(proof []byte, identity []byte, message []byte) error {
	n, v, t := modAsInt(sv.n), sv.v, sv.t
	nBytes, vBytes := sv.nBytes, sv.vBytes

	M := message

	// Stage 0 - reject proof if it's the wrong size based on t
	R, S, err := sv.decodeProof(proof)
	if err != nil {
		return fmt.Errorf("error decoding GQ proof: %w", err)
	}

	// Stage 1 - create public number G
	// currently this hardcoded to use PKCS#1 v1.5 padding as the format mechanism
	paddedIdentity := encodePKCS1v15(nBytes, identity)
	G := new(big.Int).SetBytes(paddedIdentity)

	// Stage 2 - parse signature numbers and recalculate test number W*
	// split R into t strings, each consisting of vBytes bytes
	Rs := make([]*big.Int, t)
	for i := range t {
		Rs[i] = new(big.Int).SetBytes(R[i*vBytes : (i+1)*vBytes])
	}

	// split S into t strings, each consisting of nBytes bytes
	Ss := make([]*big.Int, t)
	for i := range t {
		s_i := new(big.Int).SetBytes(S[i*nBytes : (i+1)*nBytes])
		// reject if S_i = 0 or >= n
		if s_i.Cmp(big.NewInt(0)) == 0 || s_i.Cmp(n) != -1 {
			return fmt.Errorf("GQ proof witness S_%d is out of range (must be 0 < S_i < n)", i)
		}
		Ss[i] = s_i
	}

	// recalculate test number W*
	// for i from 1 to t, compute W*_i <- S_i^v * G^{R_i} mod n
	// combine to form W*

	var Wstar []byte
	for i := range t {
		l := new(big.Int).Exp(Ss[i], v, n)
		r := new(big.Int).Exp(G, Rs[i], n)
		Wstar_i := new(big.Int).Mul(l, r)
		Wstar_i.Mod(Wstar_i, n)
		b := make([]byte, nBytes)
		Wstar = append(Wstar, Wstar_i.FillBytes(b)...)
	}

	// Stage 3 - recalculate question number R*
	// hash W* and M and take first t*vBytes bytes as R*
	Rstar, err := hash(t*vBytes, Wstar, M)
	if err != nil {
		return fmt.Errorf("error hashing GQ test number and message: %w", err)
	}

	// Stage 4 - accept or reject depending on whether R and R* are identical
	if !bytes.Equal(R, Rstar) {
		return fmt.Errorf("GQ proof is invalid: recalculated question number R* does not match the question number R in the proof")
	}
	return nil
}

func (sv *signerVerifier) VerifyJWT(jwt []byte) error {
	origHeaders, err := OriginalJWTHeaders(jwt)
	if err != nil {
		return fmt.Errorf("error retrieving original JWT headers: %w", err)
	}

	gqHeaders, payload, signature, err := oidc.SplitCompact(jwt)
	if err != nil {
		return fmt.Errorf("error splitting GQ JWT into compact segments: %w", err)
	}

	// This ensures GQ signature covers the GQ protected header so an attacker can not alter the values in the GQ protected header
	identity := util.JoinJWTSegments(origHeaders, payload)
	message := util.JoinJWTSegments(gqHeaders, payload)

	if err := sv.Verify(signature, identity, message); err != nil {
		return fmt.Errorf("error verifying GQ signature over JWT: %w", err)
	}
	return nil
}

func (sv *signerVerifier) decodeProof(s []byte) (R, S []byte, err error) {
	bin, err := util.Base64DecodeForJWT(s)
	if err != nil {
		return nil, nil, err
	}

	rSize := sv.vBytes * sv.t
	sSize := sv.nBytes * sv.t

	if len(bin) != rSize+sSize {
		return nil, nil, fmt.Errorf("not the correct size")
	}

	R = bin[:rSize]
	S = bin[rSize:]

	return R, S, nil
}
