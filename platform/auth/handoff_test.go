package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testHandoffAudience = "com.justindonnaruma.app://auth/social/callback"

func testTokenPair() *AuthResponse {
	return &AuthResponse{AccessToken: "ACCESS123", RefreshToken: "REFRESH456"}
}

// Test-list item 1: Mint -> Redeem round-trips the token pair for a valid,
// unexpired handoff.
func TestHandoffMintRedeemRoundTrip(t *testing.T) {
	jm := newTestJWTManager(t)
	store := NewInMemoryHandoffStore()

	want := testTokenPair()

	code, err := MintHandoff(t.Context(), jm, store, testHandoffAudience, want)
	if err != nil {
		t.Fatalf("MintHandoff: %v", err)
	}
	if code == "" {
		t.Fatal("MintHandoff returned an empty code")
	}

	got, err := RedeemHandoff(t.Context(), jm, store, testHandoffAudience, code)
	if err != nil {
		t.Fatalf("RedeemHandoff: %v", err)
	}
	if got.AccessToken != want.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, want.AccessToken)
	}
	if got.RefreshToken != want.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, want.RefreshToken)
	}
}

// Test-list item 2: an expired handoff CODE is refused. The TTL is pushed into
// the past at mint time rather than slept through, so the test is
// deterministic.
//
// The store entry is deliberately re-armed with a live TTL after minting. An
// earlier version of this test did not do that and was VACUOUS: minting with a
// negative TTL also expired the STORE entry, so the redeem failed with
// "unknown jti" and the test passed even when the code's own expiry was never
// enforced (proved by mutation M4, which made mint ignore the requested TTL and
// left this test green). Re-arming the store removes that confound, so the only
// thing that can refuse the redeem is the code's exp claim.
func TestHandoffExpiredIsRefused(t *testing.T) {
	jm := newTestJWTManager(t)
	store := NewInMemoryHandoffStore()

	// Positive control first: the same code shape with a live TTL redeems, so a
	// blanket-reject implementation cannot pass this test.
	live, err := mintHandoff(t.Context(), jm, store, testHandoffAudience, testTokenPair(), HandoffTTL)
	if err != nil {
		t.Fatalf("mintHandoff(live): %v", err)
	}
	if _, err := RedeemHandoff(t.Context(), jm, store, testHandoffAudience, live); err != nil {
		t.Fatalf("control: a live handoff must redeem, got %v", err)
	}

	expired, err := mintHandoff(t.Context(), jm, store, testHandoffAudience, testTokenPair(), -2*time.Minute)
	if err != nil {
		t.Fatalf("mintHandoff(expired): %v", err)
	}

	// Re-arm the store so it cannot be what does the refusing.
	jti, _ := handoffSubjectForTest(t, jm, expired)
	if err := store.Put(t.Context(), jti, testTokenPair(), time.Hour); err != nil {
		t.Fatalf("re-arm store: %v", err)
	}
	if _, err := store.Load(t.Context(), jti); err != nil {
		t.Fatalf("precondition: the store entry must be live, got %v", err)
	}

	resp, err := RedeemHandoff(t.Context(), jm, store, testHandoffAudience, expired)
	if err == nil {
		t.Fatal("SECURITY: an expired handoff code was redeemed (the store entry was live, " +
			"so nothing but the code's own exp claim could have refused it)")
	}
	if resp != nil {
		t.Fatalf("SECURITY: expired redeem returned tokens: %+v", resp)
	}
}

// TestHandoffStoreEntryExpires covers the other half of item 2 that the fix
// above deliberately factors out: even with a live code, a store entry that has
// aged past its TTL yields nothing.
func TestHandoffStoreEntryExpires(t *testing.T) {
	jm := newTestJWTManager(t)
	store := NewInMemoryHandoffStore()

	code, err := MintHandoff(t.Context(), jm, store, testHandoffAudience, testTokenPair())
	if err != nil {
		t.Fatalf("MintHandoff: %v", err)
	}
	jti, _ := handoffSubjectForTest(t, jm, code)

	// Age the entry out without touching the (still live) code.
	if err := store.Put(t.Context(), jti, testTokenPair(), -1*time.Second); err != nil {
		t.Fatalf("Put(expired): %v", err)
	}

	resp, err := RedeemHandoff(t.Context(), jm, store, testHandoffAudience, code)
	if err == nil {
		t.Fatal("an expired store entry still yielded a token pair")
	}
	if resp != nil {
		t.Fatalf("SECURITY: expired-store redeem returned tokens: %+v", resp)
	}
}

// handoffSubjectForTest decodes a handoff code's subject WITHOUT enforcing
// expiry, so a test can reach the jti of a deliberately expired code.
func handoffSubjectForTest(t *testing.T, jm *JWTManager, code string) (jti, audience string) {
	t.Helper()
	key, err := jm.stateHMACKey()
	if err != nil {
		t.Fatalf("stateHMACKey: %v", err)
	}
	claims := &jwt.RegisteredClaims{}
	if _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseWithClaims(
		code, claims, func(*jwt.Token) (interface{}, error) { return key, nil },
	); err != nil {
		t.Fatalf("parse handoff subject: %v", err)
	}
	parts := strings.Split(claims.Subject, "|")
	if len(parts) != 3 {
		t.Fatalf("unexpected handoff subject shape %q", claims.Subject)
	}
	return parts[1], parts[2]
}

// Test-list item 2b: the handoff TTL is genuinely 60 seconds, asserted on the
// minted code's own exp/iat rather than only on the constant. A code that
// silently inherited the 10-minute state TTL would be a long-lived credential
// in a URL.
func TestHandoffTTLIsSixtySeconds(t *testing.T) {
	if HandoffTTL != 60*time.Second {
		t.Fatalf("HandoffTTL = %v, want 60s", HandoffTTL)
	}

	jm := newTestJWTManager(t)
	store := NewInMemoryHandoffStore()
	code, err := MintHandoff(t.Context(), jm, store, testHandoffAudience, testTokenPair())
	if err != nil {
		t.Fatalf("MintHandoff: %v", err)
	}

	key, err := jm.stateHMACKey()
	if err != nil {
		t.Fatalf("stateHMACKey: %v", err)
	}
	claims := &jwt.RegisteredClaims{}
	if _, err := jwt.ParseWithClaims(code, claims, func(*jwt.Token) (interface{}, error) { return key, nil }); err != nil {
		t.Fatalf("parse minted handoff: %v", err)
	}
	window := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
	if window != 60*time.Second {
		t.Fatalf("minted handoff lifetime = %v, want 60s", window)
	}
}

// Test-list item 3: replay is refused, and the second redeem returns NO tokens.
// A Redeem that errors AFTER populating the response is still a replay, so this
// asserts on the response value, not merely on err != nil.
func TestHandoffReplayIsRefused(t *testing.T) {
	jm := newTestJWTManager(t)
	store := NewInMemoryHandoffStore()

	code, err := MintHandoff(t.Context(), jm, store, testHandoffAudience, testTokenPair())
	if err != nil {
		t.Fatalf("MintHandoff: %v", err)
	}

	first, err := RedeemHandoff(t.Context(), jm, store, testHandoffAudience, code)
	if err != nil {
		t.Fatalf("first redeem must succeed: %v", err)
	}
	if first.AccessToken != "ACCESS123" {
		t.Fatalf("first redeem returned the wrong pair: %+v", first)
	}

	second, err := RedeemHandoff(t.Context(), jm, store, testHandoffAudience, code)
	if err == nil {
		t.Fatal("SECURITY: a handoff code was redeemable twice — it is not single-use")
	}
	if second != nil {
		t.Fatalf("SECURITY: the replayed redeem returned tokens (%+v); "+
			"an error alongside a populated response is still a replay", second)
	}
}

// Test-list item 3b: the ReplayGuard is load-bearing, not decorative. With a
// guard that never marks anything redeemed, the SAME code redeems twice — which
// proves the passing replay test above is carried by MarkRedeemed and not by an
// incidental side effect of Load.
func TestHandoffReplayGuardIsConsulted(t *testing.T) {
	jm := newTestJWTManager(t)
	store := &neverGuardingStore{InMemoryHandoffStore: NewInMemoryHandoffStore()}

	code, err := MintHandoff(t.Context(), jm, store, testHandoffAudience, testTokenPair())
	if err != nil {
		t.Fatalf("MintHandoff: %v", err)
	}
	if _, err := RedeemHandoff(t.Context(), jm, store, testHandoffAudience, code); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if _, err := RedeemHandoff(t.Context(), jm, store, testHandoffAudience, code); err != nil {
		t.Fatalf("with a no-op ReplayGuard the second redeem should have succeeded, got %v — "+
			"single-use is being enforced somewhere other than MarkRedeemed, so the "+
			"shared-store extension seam does not actually control it", err)
	}
}

// neverGuardingStore is an InMemoryHandoffStore whose ReplayGuard always says
// "fresh". Used only by TestHandoffReplayGuardIsConsulted.
type neverGuardingStore struct{ *InMemoryHandoffStore }

func (s *neverGuardingStore) MarkRedeemed(context.Context, string, time.Duration) (bool, error) {
	return true, nil
}

// Test-list item 4: a tampered handoff is refused.
func TestHandoffTamperedSignatureIsRefused(t *testing.T) {
	jm := newTestJWTManager(t)
	store := NewInMemoryHandoffStore()

	code, err := MintHandoff(t.Context(), jm, store, testHandoffAudience, testTokenPair())
	if err != nil {
		t.Fatalf("MintHandoff: %v", err)
	}

	// Flip one bit of the DECODED signature and re-encode it. Editing a
	// character of the encoded segment is not enough: an HS256 signature is 32
	// bytes, 43 base64url characters, and the last character carries 4 data
	// bits and 2 padding bits that the non-strict decoder ignores, so a
	// last-character edit decodes to the same signature 1 time in 16.
	i := strings.LastIndex(code, ".")
	if i < 0 || i == len(code)-1 {
		t.Fatalf("unexpected handoff code shape: %q", code)
	}
	sig, err := base64.RawURLEncoding.DecodeString(code[i+1:])
	if err != nil || len(sig) == 0 {
		t.Fatalf("decode the signature segment: %v (%d bytes)", err, len(sig))
	}
	bad := bytes.Clone(sig)
	bad[len(bad)/2] ^= 0x01
	tampered := code[:i+1] + base64.RawURLEncoding.EncodeToString(bad)
	got, err := base64.RawURLEncoding.DecodeString(tampered[i+1:])
	if err != nil || bytes.Equal(got, sig) {
		t.Fatalf("tamper did not change the decoded signature (err %v)", err)
	}

	resp, err := RedeemHandoff(t.Context(), jm, store, testHandoffAudience, tampered)
	if err == nil {
		t.Fatal("SECURITY: a handoff code with a tampered signature was redeemed")
	}
	if resp != nil {
		t.Fatalf("SECURITY: tampered redeem returned tokens: %+v", resp)
	}
}

// Test-list item 5: a state JWT is not redeemable as a handoff. Two variants,
// because the two defences are independent:
//
//	5a — the real social/SSO state JWT (ML-DSA via CreateShortLivedToken) is
//	     refused by the compact validator's alg check.
//	5b — a state-SHAPED subject minted with the compact (HS256) primitive is
//	     refused by the handoff subject tag. This is the sharper case: it clears
//	     the alg check, so only the tag can reject it.
func TestHandoffStateJWTIsNotRedeemable(t *testing.T) {
	jm := newTestJWTManager(t)
	store := NewInMemoryHandoffStore()

	const stateSubject = "google|" + testHandoffAudience + "|pkce-verifier|nonce"

	mldsaState, err := jm.CreateShortLivedToken(stateSubject, 10*time.Minute)
	if err != nil {
		t.Fatalf("CreateShortLivedToken: %v", err)
	}
	compactState, err := jm.CreateCompactShortLivedToken(stateSubject, 10*time.Minute)
	if err != nil {
		t.Fatalf("CreateCompactShortLivedToken: %v", err)
	}

	for name, state := range map[string]string{
		"5a_mldsa_state_jwt":   mldsaState,
		"5b_compact_state_jwt": compactState,
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := RedeemHandoff(t.Context(), jm, store, testHandoffAudience, state)
			if err == nil {
				t.Fatal("SECURITY: a state JWT was redeemable as a handoff code")
			}
			if resp != nil {
				t.Fatalf("SECURITY: state-JWT redeem returned tokens: %+v", resp)
			}
		})
	}

	// Positive control in the same test: a genuine handoff still redeems, so
	// "refuses everything" cannot masquerade as "refuses state JWTs".
	code, err := MintHandoff(t.Context(), jm, store, testHandoffAudience, testTokenPair())
	if err != nil {
		t.Fatalf("MintHandoff: %v", err)
	}
	if _, err := RedeemHandoff(t.Context(), jm, store, testHandoffAudience, code); err != nil {
		t.Fatalf("control: a genuine handoff must still redeem, got %v", err)
	}
}

// Test-list item 5c: the subject TAG is what refuses a non-handoff token, on its
// own — not the subject's field COUNT and not a missing store entry.
//
// Mutation analysis of item 5 showed those two cases were being carried by the
// positive control and by "jti not in the store" respectively, which left the
// tag check unproven. This test removes both confounds: the forged token has
// exactly the handoff field count, exactly the right audience, and a jti that IS
// live in the store. The only thing wrong with it is the tag. If the tag check
// is dropped, this token redeems.
func TestHandoffWrongSubjectTagIsRefused(t *testing.T) {
	jm := newTestJWTManager(t)
	store := NewInMemoryHandoffStore()

	real, err := MintHandoff(t.Context(), jm, store, testHandoffAudience, testTokenPair())
	if err != nil {
		t.Fatalf("MintHandoff: %v", err)
	}
	jti, escapedAudience := handoffSubjectForTest(t, jm, real)

	forged, err := jm.CreateCompactShortLivedToken(
		strings.Join([]string{"edenstate.v1", jti, escapedAudience}, "|"), HandoffTTL)
	if err != nil {
		t.Fatalf("CreateCompactShortLivedToken: %v", err)
	}

	resp, err := RedeemHandoff(t.Context(), jm, store, testHandoffAudience, forged)
	if err == nil {
		t.Fatal("SECURITY: a token tagged for another short-lived purpose was redeemed as a " +
			"handoff — the subject tag is not being enforced, so any short-lived token this " +
			"service mints could be traded for a token pair")
	}
	if resp != nil {
		t.Fatalf("SECURITY: wrong-tag redeem returned tokens: %+v", resp)
	}

	// Control: the real code, same jti, same audience, correct tag, still works.
	if _, err := RedeemHandoff(t.Context(), jm, store, testHandoffAudience, real); err != nil {
		t.Fatalf("control: the genuine handoff must still redeem, got %v", err)
	}
}

// Test-list item 6: audience binding. A handoff minted for target A is not
// redeemable when presented for target B — with the matching positive control
// (target A redeems fine) in the same test, so the case cannot pass vacuously.
func TestHandoffAudienceBinding(t *testing.T) {
	jm := newTestJWTManager(t)
	store := NewInMemoryHandoffStore()

	const targetA = "com.justindonnaruma.app://auth/social/callback"
	const targetB = "https://evil.example/steal"

	// Negative half: minted for A, presented for B.
	forA, err := MintHandoff(t.Context(), jm, store, targetA, testTokenPair())
	if err != nil {
		t.Fatalf("MintHandoff(A): %v", err)
	}
	resp, err := RedeemHandoff(t.Context(), jm, store, targetB, forA)
	if err == nil {
		t.Fatal("SECURITY: a handoff minted for target A was redeemed for target B")
	}
	if resp != nil {
		t.Fatalf("SECURITY: cross-audience redeem returned tokens: %+v", resp)
	}

	// Positive control: the same code, presented for its own audience, redeems.
	// It must still be unspent — the rejected attempt above must NOT have burned
	// it, or a mis-targeted request becomes a denial-of-service on the user.
	got, err := RedeemHandoff(t.Context(), jm, store, targetA, forA)
	if err != nil {
		t.Fatalf("control: the handoff must redeem for its own audience, got %v", err)
	}
	if got.AccessToken != "ACCESS123" {
		t.Fatalf("control: wrong pair returned: %+v", got)
	}
}

// Test-list item 6b: the code itself carries neither token. This is the whole
// point of the change — the code travels in a URL, so anything embedded in it
// travels in that URL too.
func TestHandoffCodeContainsNoTokens(t *testing.T) {
	jm := newTestJWTManager(t)
	store := NewInMemoryHandoffStore()

	pair := &AuthResponse{
		AccessToken:  "ACCESS-SENTINEL-aaaaaaaaaaaaaaaaaaaa",
		RefreshToken: "REFRESH-SENTINEL-bbbbbbbbbbbbbbbbbbbb",
	}
	code, err := MintHandoff(t.Context(), jm, store, testHandoffAudience, pair)
	if err != nil {
		t.Fatalf("MintHandoff: %v", err)
	}

	// Both raw and base64url-decoded: a JWT payload is only encoded, not hidden.
	decoded := decodeJWTSegments(t, code)
	for _, haystack := range []string{code, decoded} {
		if strings.Contains(haystack, pair.AccessToken) {
			t.Fatalf("SECURITY: the handoff code carries the access token; it would ride in the URL. code=%q", code)
		}
		if strings.Contains(haystack, pair.RefreshToken) {
			t.Fatalf("SECURITY: the handoff code carries the refresh token; it would ride in the URL. code=%q", code)
		}
	}

	// And it must stay small enough to sit in a redirect URL without risking a
	// 414 — the hazard sso.go's fragment workaround documents.
	if len(code) > 1024 {
		t.Fatalf("handoff code is %d bytes; a code that large in a URL reintroduces the 414 hazard", len(code))
	}
}

// TestHandoffPlaintextCodeIsNeverStoredAtRest: the store is keyed by the jti,
// never by the code itself, and the code string appears nowhere in it — before
// or after redemption.
//
// This matters because the code IS a bearer credential for the 60 seconds it is
// alive. Storing it verbatim would mean a store dump (a heap snapshot, a Redis
// KEYS scan, a debug log of the replay set) hands the reader a spendable
// credential. Storing only the jti means a dump reveals which codes existed, not
// what they were.
func TestHandoffPlaintextCodeIsNeverStoredAtRest(t *testing.T) {
	jm := newTestJWTManager(t)
	store := NewInMemoryHandoffStore()

	code, err := MintHandoff(t.Context(), jm, store, testHandoffAudience, testTokenPair())
	if err != nil {
		t.Fatalf("MintHandoff: %v", err)
	}
	signature := code[strings.LastIndex(code, ".")+1:]

	check := func(when string) {
		t.Helper()
		store.mu.Lock()
		var haystack strings.Builder
		for jti, e := range store.entries {
			haystack.WriteString(jti)
			haystack.WriteString("\x00")
			haystack.WriteString(e.resp.AccessToken)
			haystack.WriteString("\x00")
			haystack.WriteString(e.resp.RefreshToken)
			haystack.WriteString("\x00")
		}
		for jti := range store.redeemed {
			haystack.WriteString(jti)
			haystack.WriteString("\x00")
		}
		store.mu.Unlock()

		at := haystack.String()
		if strings.Contains(at, code) {
			t.Fatalf("SECURITY: the plaintext handoff code is stored at rest (%s redeem); "+
				"a store dump would yield a spendable credential", when)
		}
		if strings.Contains(at, signature) {
			t.Fatalf("SECURITY: the handoff code's signature is stored at rest (%s redeem)", when)
		}
	}

	check("before")
	if _, err := RedeemHandoff(t.Context(), jm, store, testHandoffAudience, code); err != nil {
		t.Fatalf("RedeemHandoff: %v", err)
	}
	check("after")
}

// decodeJWTSegments returns the concatenated base64url-decoded header+payload
// of a JWT, so a test can look inside rather than only at the wire form.
func decodeJWTSegments(t *testing.T, token string) string {
	t.Helper()
	var out strings.Builder
	for _, seg := range strings.Split(token, ".") {
		b, err := jwt.NewParser().DecodeSegment(seg)
		if err != nil {
			continue // the signature segment is not text; skip it
		}
		out.Write(b)
	}
	return out.String()
}
