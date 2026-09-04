package authara

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var errTokenRevoked = errors.New("authara: access token is revoked")

const (
	revokedAccessTokenKeyTemplate           = "authara:access-token:revoked:token:{token_sha256}"
	revokedAccessTokenSessionKeyTemplate    = "authara:access-token:revoked:session:{session_id}"
	revokedAccessTokenUserKeyTemplate       = "authara:access-token:revoked:user:{user_id}"
	revokedAccessTokenMembershipKeyTemplate = "authara:access-token:revoked:membership:{user_id}:{organization_id}"
)

type revocationStore interface {
	GetMany(ctx context.Context, keys ...string) ([][]byte, error)
	Close() error
}

type accessTokenRevocations struct {
	store revocationStore
}

func (r *accessTokenRevocations) check(ctx context.Context, accessToken string, claims *accessClaims) error {
	if r == nil || r.store == nil {
		return nil
	}
	if claims == nil || claims.IssuedAt == nil {
		return ErrInvalidToken
	}

	keys := accessTokenRevocationKeys(accessToken, claims)
	values, err := r.store.GetMany(ctx, keys...)
	if err != nil {
		return fmt.Errorf("authara: check access token revocation: %w", err)
	}
	if len(values) != len(keys) {
		return fmt.Errorf("authara: check access token revocation: expected %d values, got %d", len(keys), len(values))
	}
	if values[0] != nil {
		return errTokenRevoked
	}

	issuedAt := claims.IssuedAt.Time.UnixNano()
	for _, value := range values[1:] {
		if value == nil {
			continue
		}
		cutoff, err := strconv.ParseInt(string(value), 10, 64)
		if err != nil {
			return fmt.Errorf("authara: check access token revocation: invalid cutoff: %w", err)
		}
		if issuedAt <= cutoff {
			return errTokenRevoked
		}
	}
	return nil
}

func accessTokenRevocationKeys(accessToken string, claims *accessClaims) []string {
	sum := sha256.Sum256([]byte(accessToken))
	tokenHash := hex.EncodeToString(sum[:])
	return []string{
		expandRevocationKey(revokedAccessTokenKeyTemplate,
			"{token_sha256}", tokenHash,
		),
		expandRevocationKey(revokedAccessTokenSessionKeyTemplate,
			"{session_id}", claims.SessionID.String(),
		),
		expandRevocationKey(revokedAccessTokenUserKeyTemplate,
			"{user_id}", claims.Subject,
		),
		expandRevocationKey(revokedAccessTokenMembershipKeyTemplate,
			"{user_id}", claims.Subject,
			"{organization_id}", claims.OrgID.String(),
		),
	}
}

func expandRevocationKey(template string, replacements ...string) string {
	return strings.NewReplacer(replacements...).Replace(template)
}
