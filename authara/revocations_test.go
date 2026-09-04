package authara

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type revocationContractSpec struct {
	Token      string `json:"token"`
	Session    string `json:"session"`
	User       string `json:"user"`
	Membership string `json:"membership"`
}

func TestAccessTokenRevocationsMatchCoreContract(t *testing.T) {
	contract := loadRevocationContract(t)
	accessToken := "secret-token"
	issuedAt := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	claims := &accessClaims{
		SessionID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		OrgID:     uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "22222222-2222-2222-2222-222222222222",
			IssuedAt: jwt.NewNumericDate(issuedAt),
		},
	}
	sum := sha256.Sum256([]byte(accessToken))
	wantKeys := []string{
		contractKey(contract.Token, "{token_sha256}", hex.EncodeToString(sum[:])),
		contractKey(contract.Session, "{session_id}", claims.SessionID.String()),
		contractKey(contract.User, "{user_id}", claims.Subject),
		contractKey(contract.Membership,
			"{user_id}", claims.Subject, "{organization_id}", claims.OrgID.String()),
	}
	if got := accessTokenRevocationKeys(accessToken, claims); !reflect.DeepEqual(got, wantKeys) {
		t.Fatalf("SDK keys differ from Core contract:\n got: %v\nwant: %v", got, wantKeys)
	}

	cutoff := []byte("1786104000000000000")
	for _, tt := range []struct {
		name   string
		values map[string][]byte
		want   error
	}{
		{name: "not revoked", values: map[string][]byte{}},
		{name: "token", values: map[string][]byte{wantKeys[0]: []byte("1")}, want: errTokenRevoked},
		{name: "session", values: map[string][]byte{wantKeys[1]: cutoff}, want: errTokenRevoked},
		{name: "user", values: map[string][]byte{wantKeys[2]: cutoff}, want: errTokenRevoked},
		{name: "membership", values: map[string][]byte{wantKeys[3]: cutoff}, want: errTokenRevoked},
		{name: "newer token", values: map[string][]byte{wantKeys[1]: []byte("1786103999999999999")}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeRevocationStore{values: tt.values}
			err := (&accessTokenRevocations{store: store}).check(context.Background(), accessToken, claims)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			if !reflect.DeepEqual(store.keys, wantKeys) {
				t.Fatalf("lookup order differs from contract: got %v, want %v", store.keys, wantKeys)
			}
		})
	}

	lookupErr := errors.New("redis unavailable")
	if err := (&accessTokenRevocations{store: &fakeRevocationStore{err: lookupErr}}).
		check(context.Background(), accessToken, claims); !errors.Is(err, lookupErr) {
		t.Fatalf("revocation lookup must fail closed: %v", err)
	}
}

func loadRevocationContract(t *testing.T) revocationContractSpec {
	t.Helper()
	data, err := os.ReadFile("../.codegen/access-token-revocations.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var contract revocationContractSpec
	if err := decoder.Decode(&contract); err != nil {
		t.Fatal(err)
	}
	return contract
}

func contractKey(template string, replacements ...string) string {
	return strings.NewReplacer(replacements...).Replace(template)
}

type fakeRevocationStore struct {
	values map[string][]byte
	err    error
	keys   []string
}

func (s *fakeRevocationStore) GetMany(_ context.Context, keys ...string) ([][]byte, error) {
	s.keys = append([]string(nil), keys...)
	if s.err != nil {
		return nil, s.err
	}
	values := make([][]byte, len(keys))
	for i, key := range keys {
		values[i] = s.values[key]
	}
	return values, nil
}

func (*fakeRevocationStore) Close() error { return nil }
