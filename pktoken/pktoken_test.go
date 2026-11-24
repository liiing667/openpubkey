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

package pktoken_test

import (
	"bytes"
	"crypto"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/providers"
	provmocks "github.com/openpubkey/openpubkey/providers/mocks"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/openpubkey/openpubkey/util"
)

func TestPkToken(t *testing.T) {
	alg := jose.ES256

	signingKey, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	pkt, err := mocks.GenerateMockPKToken(t, signingKey, alg)
	require.NoError(t, err)

	testPkTokenMessageSigning(t, pkt, signingKey)
	testPkTokenSerialization(t, pkt)

	actualIssuer, err := pkt.Issuer()
	require.NoError(t, err)
	require.Equal(t, "mockIssuer", actualIssuer)

	actualAudience, err := pkt.Audience()
	require.NoError(t, err)
	require.Equal(t, "empty", actualAudience)

	actualAlg, ok := pkt.ProviderAlgorithm()
	require.True(t, ok)
	require.Equal(t, jose.RS256, actualAlg)

}

func testPkTokenMessageSigning(t *testing.T, pkt *pktoken.PKToken, signingKey crypto.Signer) {
	// Create new OpenPubKey Signed Message (OSM)
	msg := "test message!"
	osm, err := pkt.NewSignedMessage([]byte(msg), signingKey)
	require.NoError(t, err)

	// Verify our OSM is valid
	payload, err := pkt.VerifySignedMessage(osm)
	require.NoError(t, err)

	require.Equal(t, msg, string(payload), "OSM payload did not match what we initially wrapped")
}

func testPkTokenSerialization(t *testing.T, pkt *pktoken.PKToken) {
	// Test json serialization/deserialization
	pktJson, err := json.Marshal(pkt)
	require.NoError(t, err)

	var newPkt *pktoken.PKToken
	err = json.Unmarshal(pktJson, &newPkt)
	require.NoError(t, err)

	newPktJson, err := json.Marshal(newPkt)
	require.NoError(t, err)

	require.JSONEq(t, string(pktJson), string(newPktJson))

	// Simple Compact sanity test
	pktCom, err := pkt.Compact()
	require.NoError(t, err)
	require.NotNil(t, pktCom)

	pktFromCom, err := pktoken.NewFromCompact(pktCom)
	require.NoError(t, err)
	require.NotNil(t, pktFromCom.OpToken)
	require.NotNil(t, pktFromCom.CicToken)
}

// This test builds a PK Token from a set of test vectors and then checks
// that our serialization code preserves the exact values supplied as
// test vectors. This is input because even minor whitespace or ordering
// changes can break signature verification.
func TestPkTokenJwsUnchanged(t *testing.T) {
	payload := `{
		"aud": "testAud",
		"email": "arthur.aardvark@example.com",
		"exp": 1708641372,
		"iat": 1708554972,
		"iss": "mockIssuer",
		"nonce": "iOqVQfpJsbt4gpcGUX0lJLT82bTm8PU1fwNghiGau0M",
		"sub": "1234567890"
	  }`

	testCases := []struct {
		name         string
		payload      string
		opProtected  string
		cicProtected string
		cosProtected string
	}{
		{name: "with alphabetical order",
			payload:      payload,
			opProtected:  `{"alg":"RS256","typ":"JWT"}`,
			cicProtected: `{"alg":"ES256","rz":"872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e","typ":"CIC","upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}}`,
			cosProtected: `{"alg":"ES256","auth_time":1708991378,"eid":"1234","exp":1708994978,"iat":1708991378,"iss":"example.com","kid":"1234","nonce":"test-nonce","ruri":"http://localhost:3000","typ":"COS"}`,
		},
		{name: "with reverse alphabetical order",
			payload:      payload,
			opProtected:  `{"typ":"JWT","alg":"RS256"}`,
			cicProtected: `{"upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}, "typ":"CIC", "rz":"872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e", "alg":"ES256"}`,
			cosProtected: `{"typ":"COS","ruri":"http://localhost:3000","nonce":"test-nonce","kid":"1234","iss":"example.com","iat":1708991378,"exp":1708994978,"eid":"none","auth_time":1708991378,"alg":"ES256"}`,
		},
		{name: "with extra whitespace",
			payload:      payload,
			opProtected:  `{  "alg" : "RS256",     "typ": "JWT" }`,
			cicProtected: `{  "alg" : "ES256",  "rz": "872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e" , "typ":"CIC","upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}}`,
			cosProtected: `{  "alg" : "ES256",  "auth_time": 1708991378,"eid":"1234","exp":1708994978,"iat":1708991378,"iss":"example.com","kid":"1234","nonce":"test-nonce","ruri":"http://localhost:3000","typ":"COS"}`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testUnchanged(t, tc.payload, tc.opProtected, tc.cicProtected, tc.cosProtected)
		})
	}
}

func testUnchanged(t *testing.T, payload string, opPheader string, cicPheader string, cosPheader string) {
	pkt := &pktoken.PKToken{}

	// Build OP Token and add it to PK Token
	opTokenOriginal := BuildToken(opPheader, payload, "fakeSignature OP")
	err := pkt.AddSignature(opTokenOriginal, pktoken.OIDC)
	require.NoError(t, err)

	// Build CIC Token and add it to PK Token
	cicTokenOriginal := BuildToken(cicPheader, payload, "fakeSignature")
	err = pkt.AddSignature(cicTokenOriginal, pktoken.CIC)
	require.NoError(t, err)

	// Build CIC Token and add it to PK Token
	cosTokenOriginal := BuildToken(cosPheader, payload, "fakeSignature")
	err = pkt.AddSignature(cosTokenOriginal, pktoken.COS)
	require.NoError(t, err)

	// Check that Marshal PK Token to Json leaves underlying signed values unchanged
	pktJson, err := pkt.MarshalJSON()
	require.NoError(t, err)

	// Unmarshal it into a simple JWS structure to see if the underlying values have changed
	var simpleJWS oidc.Jws
	err = json.Unmarshal(pktJson, &simpleJWS)
	require.NoError(t, err)

	opTokenUnmarshalled, err := simpleJWS.GetTokenByTyp("JWT") // JWT is the token typ used by the OP Token (ID Token)
	require.NoError(t, err)
	require.EqualValues(t, string(opTokenOriginal), string(opTokenUnmarshalled), "danger, signed values in OP Token being changed during marshalling")

	cicTokenUnmarshalled, err := simpleJWS.GetTokenByTyp("CIC") // CIC is the token typ used by the OP Token (ID Token)
	require.NoError(t, err)
	require.EqualValues(t, string(cicTokenOriginal), string(cicTokenUnmarshalled), "danger, signed values in CIC Token being changed during marshalling")

	cosTokenUnmarshalled, err := simpleJWS.GetTokenByTyp("COS") // COS is the token typ used by the OP Token (ID Token)
	require.NoError(t, err)
	require.EqualValues(t, string(cosTokenOriginal), string(cosTokenUnmarshalled), "danger, signed values in CIC Token being changed during marshalling")

	// Check that ToCompact and FromCompact leaves underlying signed values unchanged
	pktCom, err := pkt.Compact()
	require.NoError(t, err)
	pktFromCom, err := pktoken.NewFromCompact(pktCom)
	require.NoError(t, err)

	require.EqualValues(t, string(opTokenOriginal), string(pktFromCom.OpToken), "danger, signed values in OP Token being changed after compact")
	require.EqualValues(t, string(cicTokenOriginal), string(pktFromCom.CicToken), "danger, signed values in CIC Token being changed after compact")
	require.EqualValues(t, string(cosTokenOriginal), string(pktFromCom.CosToken), "danger, signed values in COS Token being changed after compact")
}

// This test builds a PK Token from a set of test vectors and then checks
// that the ToCompact constructs the PK Token correctly and that FromCompact
// reconstructs the PK Token correctly.
func TestCompact(t *testing.T) {
	payload := `{
		"aud": "testAud",
		"email": "arthur.aardvark@example.com",
		"exp": 1708641372,
		"iat": 1708554972,
		"iss": "mockIssuer",
		"nonce": "iOqVQfpJsbt4gpcGUX0lJLT82bTm8PU1fwNghiGau0M",
		"sub": "1234567890"
	  }`

	testCases := []struct {
		name                string
		payload             string
		opProtected         string
		cicProtected        string
		cosProtected        string
		expToCompactError   string
		expFromCompactError string
	}{
		{name: "Happy case with OP, CIC tokens",
			payload:      payload,
			opProtected:  `{"alg":"RS256","typ":"JWT"}`,
			cicProtected: `{"alg":"ES256","rz":"872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e","typ":"CIC","upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}}`,
		},
		{name: "Happy case with key binding OP, CIC tokens",
			payload:      payload,
			opProtected:  `{"alg":"RS256","typ":"dpop+id_token","cnf":{"jwk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}}}`,
			cicProtected: `{"alg":"ES256","rz":"872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e","typ":"CIC","upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}}`,
		},
		{name: "Happy case with OP, CIC and COS tokens",
			payload:      payload,
			opProtected:  `{"alg":"RS256","typ":"JWT"}`,
			cicProtected: `{"alg":"ES256","rz":"872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e","typ":"CIC","upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}}`,
			cosProtected: `{"alg":"ES256","auth_time":1708991378,"eid":"1234","exp":1708994978,"iat":1708991378,"iss":"example.com","kid":"1234","nonce":"test-nonce","ruri":"http://localhost:3000","typ":"COS"}`,
		},
		{name: "No Tokens",
			expToCompactError: "no tokens provided",
			payload:           payload,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := &pktoken.PKToken{}

			tokensAdded := 0
			// Let's us test the case with no CIC Token.
			if tc.opProtected != "" {
				// Build OP Token and add it to PK Token
				opTokenOriginal := BuildToken(tc.opProtected, tc.payload, "fakeSignature OP")
				err := pkt.AddSignature(opTokenOriginal, pktoken.OIDC)
				require.NoError(t, err)
				tokensAdded += 1
			}

			// Let's us test the case with no CIC Token.
			if tc.cicProtected != "" {
				// Build CIC Token and add it to PK Token
				cicTokenOriginal := BuildToken(tc.cicProtected, payload, "fakeSignature")
				err := pkt.AddSignature(cicTokenOriginal, pktoken.CIC)
				require.NoError(t, err)
				tokensAdded += 1
			}

			// Let's us test the case with no COS Token. This is not an error case.
			if tc.cosProtected != "" {
				// Build CIC Token and add it to PK Token
				cosTokenOriginal := BuildToken(tc.cosProtected, payload, "fakeSignature")
				err := pkt.AddSignature(cosTokenOriginal, pktoken.COS)
				require.NoError(t, err)
				tokensAdded += 1
			}

			pktCom, err := pkt.Compact()
			if tc.expToCompactError != "" {
				require.ErrorContains(t, err, tc.expToCompactError)
			} else {
				require.NoError(t, err)
				require.NotNil(t, pktCom)
				parts := bytes.Split(pktCom, []byte(":"))
				expParts := tokensAdded*2 + 1
				require.Equal(t, expParts, len(parts), "number of expected parts in compact (%d) does not match number of parts found (%d) ", expParts, len(parts))

				// Try build a PK Token from the compact representation
				pktFromCom, err := pktoken.NewFromCompact(pktCom)
				if tc.expFromCompactError != "" {
					require.ErrorContains(t, err, tc.expFromCompactError)
				} else {
					require.NoError(t, err)
					require.NotNil(t, pktFromCom)

					require.Equal(t, pkt.OpToken, pktFromCom.OpToken)
					require.Equal(t, pkt.Op, pktFromCom.Op)

					require.Equal(t, pkt.CicToken, pktFromCom.CicToken)
					require.Equal(t, pkt.Cic, pktFromCom.Cic)

					require.Equal(t, pkt.CosToken, pktFromCom.CosToken)
					require.Equal(t, pkt.Cos, pktFromCom.Cos)

					actualIssuer, err := pktFromCom.Issuer()
					require.NoError(t, err)
					require.Equal(t, "mockIssuer", actualIssuer)
				}

				// Test Deep Copy
				pktCopy1, err := pkt.DeepCopy()
				require.NoError(t, err)
				pktCopy2, err := pkt.DeepCopy()
				require.NoError(t, err)
				require.Equal(t, pktCopy1.OpToken, pktCopy2.OpToken)
				require.Equal(t, pktCopy1.Op, pktCopy2.Op)
				require.Equal(t, pktCopy1.FreshIDToken, pktCopy2.FreshIDToken)

				pktCopy1.OpToken = []byte("Overwritten-OP-Token")
				pktCopy1.Op.SetSignature([]byte{0x0})
				pktCopy1.FreshIDToken = []byte("Overwritten-Fresh-ID-Token")

				require.NotEqual(t, pktCopy1.OpToken, pktCopy2.OpToken)
				require.NotEqual(t, pktCopy1.Op, pktCopy2.Op)
				require.NotEqual(t, pktCopy1.FreshIDToken, pktCopy2.FreshIDToken)
			}

		})
	}
}

//go:embed test_jwk.json
var test_jwk []byte

// based on https://www.rfc-editor.org/rfc/rfc7638.html
func TestThumprintCalculation(t *testing.T) {
	fromRfc := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	pub, err := jwk.ParseKey(test_jwk)
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	thumbEnc := util.Base64EncodeForJWT(thumb)
	if string(thumbEnc) != fromRfc {
		t.Fatalf("thumbprint %s did not match expected value %s", thumbEnc, fromRfc)
	}

}

// TestAtJWTTokenType verifies that PKTokens whose OP signature carries
// typ "at+JWT" (RFC 9068 access tokens) are handled correctly.
// Both NewFromCompact and UnmarshalJSON (exercised via DeepCopy) must
// treat "at+JWT" as equivalent to "JWT" (OIDC).
func TestAtJWTTokenType(t *testing.T) {
	alg := jose.ES256
	signingKey, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	idtTemplate := provmocks.DefaultIDTokenTemplate()
	idtTemplate.ExtraProtectedClaims = map[string]any{"typ": "at+JWT"}

	opts := &mocks.MockPKTokenOpts{
		GQSign:         false,
		CommitType:     providers.CommitTypesEnum.NONCE_CLAIM,
		CorrectCicHash: true,
		CorrectCicSig:  true,
	}
	pkt, _, err := mocks.GenerateMockPKTokenWithOpts(t, signingKey, alg, idtTemplate, opts)
	require.NoError(t, err)

	t.Run("NewFromCompact", func(t *testing.T) {
		pktCom, err := pkt.Compact()
		require.NoError(t, err)

		pktFromCom, err := pktoken.NewFromCompact(pktCom)
		require.NoError(t, err)
		require.NotNil(t, pktFromCom.OpToken)
		require.NotNil(t, pktFromCom.CicToken)
	})

	t.Run("UnmarshalJSON", func(t *testing.T) {
		pktJSON, err := json.Marshal(pkt)
		require.NoError(t, err)

		var pktCopy pktoken.PKToken
		require.NoError(t, json.Unmarshal(pktJSON, &pktCopy))
		require.NotNil(t, pktCopy.OpToken)
		require.NotNil(t, pktCopy.CicToken)
	})

	t.Run("DeepCopy", func(t *testing.T) {
		pktCopy, err := pkt.DeepCopy()
		require.NoError(t, err)
		require.NotNil(t, pktCopy.OpToken)
		require.NotNil(t, pktCopy.CicToken)
	})
}

func BuildToken(protected string, payload string, sig string) []byte {
	return util.JoinJWTSegments(
		util.Base64EncodeForJWT([]byte(protected)),
		util.Base64EncodeForJWT([]byte(payload)),
		util.Base64EncodeForJWT([]byte(sig)))
}

// compactToJSON round-trips a compact PK Token through the JSON entry point.
// It is used to assert that both entry points interpret the same bytes
// identically.
func compactToJSON(t *testing.T, pktCom []byte) []byte {
	pktFromCom, err := pktoken.NewFromCompact(pktCom)
	require.NoError(t, err)
	pktJSON, err := json.Marshal(pktFromCom)
	require.NoError(t, err)
	return pktJSON
}

// TestEntryPointEquivalence verifies that feeding the very same compact PK
// Token bytes through both entry points (NewFromCompact and UnmarshalJSON)
// produces equivalent PK Tokens. This is the core matrix the bug report
// describes: signature type classification, payload ownership and the
// re-encoding of the signed segments must not depend on the entry point.
func TestEntryPointEquivalence(t *testing.T) {
	alg := jose.ES256
	signingKey, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	pkt, err := mocks.GenerateMockPKToken(t, signingKey, alg)
	require.NoError(t, err)

	// Include a fresh ID Token so that the fresh appended segment is covered
	// by the equivalence check as well.
	freshIDToken := BuildToken(`{"alg":"RS256","typ":"JWT"}`,
		`{"iss":"mockIssuer","sub":"1234567890","exp":1900000000}`, "fake fresh sig")
	pkt.FreshIDToken = freshIDToken

	pktCom, err := pkt.Compact()
	require.NoError(t, err)

	// Entry point 1: compact
	pktFromCom, err := pktoken.NewFromCompact(pktCom)
	require.NoError(t, err)

	// Entry point 2: JSON (marshal the compact-parsed token, then parse the JSON)
	pktJSON, err := json.Marshal(pktFromCom)
	require.NoError(t, err)
	var pktFromJSON pktoken.PKToken
	require.NoError(t, json.Unmarshal(pktJSON, &pktFromJSON))

	// The re-encoded signed segments must be byte identical regardless of the
	// entry point; any change breaks signature verification.
	require.Equal(t, pktFromCom.OpToken, pktFromJSON.OpToken)
	require.Equal(t, pktFromCom.CicToken, pktFromJSON.CicToken)
	require.Equal(t, pktFromCom.CosToken, pktFromJSON.CosToken)
	require.Equal(t, pktFromCom.Payload, pktFromJSON.Payload)

	// And the round trip back to compact must be stable.
	pktComAgain, err := pktFromJSON.Compact()
	require.NoError(t, err)
	require.Equal(t, pktCom, pktComAgain)

	// The fresh ID Token is owned separately and must survive both paths.
	require.Equal(t, freshIDToken, pktFromCom.FreshIDToken)

	// Re-marshalling the JSON-parsed token must reproduce the same JSON.
	pktJSONAgain, err := json.Marshal(&pktFromJSON)
	require.NoError(t, err)
	require.JSONEq(t, string(pktJSON), string(pktJSONAgain))
}

// TestDuplicateSegmentsRejected ensures that repeated CIC/OIDC/COS segments
// are rejected by the compact entry point just like the JSON entry point,
// instead of silently overwriting an earlier signature of the same type.
func TestDuplicateSegmentsRejected(t *testing.T) {
	payload := `{"iss":"mockIssuer","sub":"1234567890","nonce":"abc","exp":1900000000}`

	opToken := BuildToken(`{"alg":"RS256","typ":"JWT"}`, payload, "op sig")
	cicToken1 := BuildToken(`{"alg":"ES256","typ":"CIC","upk":{}}`, payload, "cic sig 1")
	cicToken2 := BuildToken(`{"alg":"ES256","typ":"CIC","upk":{}}`, payload, "cic sig 2")

	// Compact representation with two CIC segments (same payload, duplicated
	// protected/signature pairs).
	com, err := pktoken.CompactPKToken([][]byte{opToken, cicToken1, cicToken2}, nil)
	require.NoError(t, err)

	var pkt *pktoken.PKToken
	pkt, err = pktoken.NewFromCompact(com)
	require.Error(t, err)
	require.ErrorContains(t, err, "only one signature of type \"cic\" is allowed")
	require.Nil(t, pkt, "a failed parse must not return a half-populated PK Token")
}

// TestNewFromCompactAtomicOnFailure checks that no failure mode of
// NewFromCompact leaks a partially populated PK Token and that malformed
// compact inputs are rejected before any state is committed.
func TestNewFromCompactAtomicOnFailure(t *testing.T) {
	payload := `{"iss":"mockIssuer","sub":"1234567890","nonce":"abc","exp":1900000000}`

	t.Run("unrecognized signature type", func(t *testing.T) {
		opToken := BuildToken(`{"alg":"RS256","typ":"JWT"}`, payload, "op sig")
		bogusToken := BuildToken(`{"alg":"ES256","typ":"NOPE"}`, payload, "bogus sig")
		com, err := pktoken.CompactPKToken([][]byte{opToken, bogusToken}, nil)
		require.NoError(t, err)

		pkt, err := pktoken.NewFromCompact(com)
		require.Error(t, err)
		require.ErrorContains(t, err, "unrecognized signature type")
		require.Nil(t, pkt)
	})

	t.Run("missing CIC segment", func(t *testing.T) {
		opToken := BuildToken(`{"alg":"RS256","typ":"JWT"}`, payload, "op sig")
		com, err := pktoken.CompactPKToken([][]byte{opToken}, nil)
		require.NoError(t, err)

		pkt, err := pktoken.NewFromCompact(com)
		require.Error(t, err)
		require.ErrorContains(t, err, "at least one signature of type \"cic\" is required")
		require.Nil(t, pkt)
	})

	t.Run("payload mismatch is rejected and leaves no half object", func(t *testing.T) {
		opToken := BuildToken(`{"alg":"RS256","typ":"JWT"}`, payload, "op sig")
		otherPayload := `{"iss":"mockIssuer","sub":"999","nonce":"abc","exp":1900000000}`
		cicToken := BuildToken(`{"alg":"ES256","typ":"CIC","upk":{}}`, otherPayload, "cic sig")

		// CompactPKToken owns payload equality up front: every signed segment
		// must share the same payload or serialization is refused.
		_, err := pktoken.CompactPKToken([][]byte{opToken, cicToken}, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "payloads in tokens are not the same")
	})

	t.Run("invalid refreshed ID Token", func(t *testing.T) {
		opToken := BuildToken(`{"alg":"RS256","typ":"JWT"}`, payload, "op sig")
		cicToken := BuildToken(`{"alg":"ES256","typ":"CIC","upk":{}}`, payload, "cic sig")
		com, err := pktoken.CompactPKToken([][]byte{opToken, cicToken}, nil)
		require.NoError(t, err)

		// Hand-craft a compact PK Token whose appended fresh segment is not a
		// three-part JWT and confirm the parse entry point rejects it without
		// returning a PK Token.
		badCompact := append(append([]byte{}, com...), []byte(".NOT.A.VALID.JWT")...)
		pkt, err := pktoken.NewFromCompact(badCompact)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid refreshed ID Token")
		require.Nil(t, pkt)
	})
}

// TestUnmarshalJSONAtomicOnFailure verifies the JSON entry point never leaves
// a half-populated PK Token behind when parsing fails.
func TestUnmarshalJSONAtomicOnFailure(t *testing.T) {
	alg := jose.ES256
	signingKey, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	pkt, err := mocks.GenerateMockPKToken(t, signingKey, alg)
	require.NoError(t, err)

	goodJSON, err := json.Marshal(pkt)
	require.NoError(t, err)

	// Corrupt the JSON so that a signature carries an unknown typ.
	var raw map[string]any
	require.NoError(t, json.Unmarshal(goodJSON, &raw))
	sigs := raw["signatures"].([]any)
	for _, s := range sigs {
		sigMap := s.(map[string]any)
		protectedB64 := sigMap["protected"].(string)
		protectedJSON, err := util.Base64DecodeForJWT([]byte(protectedB64))
		require.NoError(t, err)
		var headers map[string]any
		require.NoError(t, json.Unmarshal(protectedJSON, &headers))
		if _, ok := headers["typ"]; ok {
			headers["typ"] = "UNSUPPORTED-TYP"
			newProtected, err := json.Marshal(headers)
			require.NoError(t, err)
			sigMap["protected"] = string(util.Base64EncodeForJWT(newProtected))
		}
	}
	badJSON, err := json.Marshal(raw)
	require.NoError(t, err)

	// Seed a valid token first, then attempt to overwrite it with bad data.
	var target pktoken.PKToken
	require.NoError(t, json.Unmarshal(goodJSON, &target))
	require.NotNil(t, target.OpToken)

	err = json.Unmarshal(badJSON, &target)
	require.Error(t, err)
	require.ErrorContains(t, err, "unrecognized signature type")

	// The previously valid state must be preserved: a failed unmarshal must
	// not mutate the target into a half object.
	require.NotNil(t, target.OpToken)
	require.NotNil(t, target.CicToken)
}

// TestMissingTypTreatedAsOIDCCompact confirms that old compact PK Tokens whose
// OP signature omits the "typ" header (e.g. Okta) still parse and are
// classified as OIDC through the compact entry point.
func TestMissingTypTreatedAsOIDCCompact(t *testing.T) {
	payload := `{"iss":"mockIssuer","sub":"1234567890","nonce":"abc","exp":1900000000}`

	// OP token with no typ claim.
	opToken := BuildToken(`{"alg":"RS256"}`, payload, "op sig")
	cicToken := BuildToken(`{"alg":"ES256","typ":"CIC","upk":{}}`, payload, "cic sig")

	com, err := pktoken.CompactPKToken([][]byte{opToken, cicToken}, nil)
	require.NoError(t, err)

	pkt, err := pktoken.NewFromCompact(com)
	require.NoError(t, err)
	require.NotNil(t, pkt.Op)
	require.NotNil(t, pkt.OpToken)
	require.NotNil(t, pkt.CicToken)
	// The re-encoded OP token keeps the original typ-less protected header.
	require.Equal(t, opToken, pkt.OpToken)
}

// TestAtJWTEntryPointEquivalence checks that an "at+jwt" (RFC 9068, in any
// casing) OP signature is treated as OIDC by both entry points and that the
// original protected header is preserved byte-for-byte during re-encoding.
func TestAtJWTEntryPointEquivalence(t *testing.T) {
	payload := `{"iss":"mockIssuer","sub":"1234567890","nonce":"abc","exp":1900000000}`

	for _, typ := range []string{"at+jwt", "AT+JWT", "At+JwT"} {
		t.Run(typ, func(t *testing.T) {
			opToken := BuildToken(`{"alg":"RS256","typ":"`+typ+`"}`, payload, "op sig")
			cicToken := BuildToken(`{"alg":"ES256","typ":"CIC","upk":{}}`, payload, "cic sig")

			com, err := pktoken.CompactPKToken([][]byte{opToken, cicToken}, nil)
			require.NoError(t, err)

			pktFromCom, err := pktoken.NewFromCompact(com)
			require.NoError(t, err)
			require.NotNil(t, pktFromCom.OpToken)
			// Re-encoding must preserve the exact original protected header.
			require.Equal(t, opToken, pktFromCom.OpToken)

			// Same bytes via the JSON entry point must classify identically.
			pktJSON := compactToJSON(t, com)
			var pktFromJSON pktoken.PKToken
			require.NoError(t, json.Unmarshal(pktJSON, &pktFromJSON))
			require.NotNil(t, pktFromJSON.OpToken)
			require.Equal(t, pktFromCom.OpToken, pktFromJSON.OpToken)
		})
	}
}

// TestKeyBoundEntryPointEquivalence ensures the OIDCKB ("dpop+id_token")
// signature type is routed to the OP slot through both entry points and that
// re-encoding preserves the signed segments.
func TestKeyBoundEntryPointEquivalence(t *testing.T) {
	payload := `{"iss":"mockIssuer","sub":"1234567890","nonce":"abc","exp":1900000000}`

	opToken := BuildToken(
		`{"alg":"RS256","typ":"dpop+id_token","cnf":{"jwk":{"kty":"EC","crv":"P-256","x":"x","y":"y"}}}`,
		payload, "op sig")
	cicToken := BuildToken(`{"alg":"ES256","typ":"CIC","upk":{}}`, payload, "cic sig")

	com, err := pktoken.CompactPKToken([][]byte{opToken, cicToken}, nil)
	require.NoError(t, err)

	// Compact entry point: key bound token lands in the OP slot.
	pktFromCom, err := pktoken.NewFromCompact(com)
	require.NoError(t, err)
	require.NotNil(t, pktFromCom.Op)
	require.Nil(t, pktFromCom.Cos)
	require.Equal(t, opToken, pktFromCom.OpToken)
	require.Equal(t, cicToken, pktFromCom.CicToken)

	// JSON entry point on the equivalent general JWS must agree.
	pktJSON := compactToJSON(t, com)
	var pktFromJSON pktoken.PKToken
	require.NoError(t, json.Unmarshal(pktJSON, &pktFromJSON))
	require.NotNil(t, pktFromJSON.Op)
	require.Equal(t, pktFromCom.OpToken, pktFromJSON.OpToken)
	require.Equal(t, pktFromCom.CicToken, pktFromJSON.CicToken)
}

// TestDuplicateOIDCSegmentsRejected verifies that a compact PK Token carrying
// two OIDC segments is rejected rather than having the second silently
// overwrite the first.
func TestDuplicateOIDCSegmentsRejected(t *testing.T) {
	payload := `{"iss":"mockIssuer","sub":"1234567890","nonce":"abc","exp":1900000000}`

	opToken1 := BuildToken(`{"alg":"RS256","typ":"JWT"}`, payload, "op sig 1")
	opToken2 := BuildToken(`{"alg":"RS256","typ":"JWT","kid":"other"}`, payload, "op sig 2")
	cicToken := BuildToken(`{"alg":"ES256","typ":"CIC","upk":{}}`, payload, "cic sig")

	com, err := pktoken.CompactPKToken([][]byte{opToken1, opToken2, cicToken}, nil)
	require.NoError(t, err)

	pkt, err := pktoken.NewFromCompact(com)
	require.Error(t, err)
	require.ErrorContains(t, err, "only one signature of type \"oidc\" or \"oidc_gq\" is allowed")
	require.Nil(t, pkt)
}

// TestFreshIDTokenRoundTrip confirms the fresh (refreshed) ID Token segment is
// appended on serialization and restored separately on parsing without ever
// being mixed into the shared PK Token payload.
func TestFreshIDTokenRoundTrip(t *testing.T) {
	payload := `{"iss":"mockIssuer","sub":"1234567890","nonce":"abc","exp":1700000000}`

	opToken := BuildToken(`{"alg":"RS256","typ":"JWT"}`, payload, "op sig")
	cicToken := BuildToken(`{"alg":"ES256","typ":"CIC","upk":{}}`, payload, "cic sig")
	// The fresh token intentionally carries a different payload.
	freshToken := BuildToken(`{"alg":"RS256","typ":"JWT"}`,
		`{"iss":"mockIssuer","sub":"1234567890","exp":1900000000}`, "fresh sig")

	com, err := pktoken.CompactPKToken([][]byte{opToken, cicToken}, freshToken)
	require.NoError(t, err)

	pkt, err := pktoken.NewFromCompact(com)
	require.NoError(t, err)
	require.Equal(t, freshToken, pkt.FreshIDToken)

	// Re-serializing must reproduce the exact compact bytes, fresh segment
	// included, proving nothing was re-encoded or re-owned.
	comAgain, err := pkt.Compact()
	require.NoError(t, err)
	require.Equal(t, com, comAgain)

	// The main payload is untouched by the fresh token's distinct payload.
	require.Equal(t, util.Base64EncodeForJWT([]byte(payload)),
		util.Base64EncodeForJWT(pkt.Payload))
}
