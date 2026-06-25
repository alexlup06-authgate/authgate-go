package authara

import (
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type accessClaims struct {
	SessionID uuid.UUID `json:"sid"`
	OrgID     uuid.UUID `json:"org_id"`
	OrgRole   string    `json:"org_role"`
	Roles     []string  `json:"roles"`

	jwt.RegisteredClaims
}

type accessIdentity struct {
	UserID           uuid.UUID
	OrganizationID   uuid.UUID
	OrganizationRole string
	Roles            []string
}

type verifier struct {
	issuer   string
	audience string
	keys     map[string][]byte
}

func newVerifier(cfg Config) (*verifier, error) {
	return &verifier{
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		keys:     cfg.Keys,
	}, nil
}

func (v *verifier) verify(tokenString string) (accessIdentity, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithLeeway(clockSkew),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
	)

	token, err := parser.ParseWithClaims(
		tokenString,
		&accessClaims{},
		v.keyFunc,
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return accessIdentity{}, ErrTokenExpired
		}
		return accessIdentity{}, ErrInvalidToken
	}

	claims, ok := token.Claims.(*accessClaims)
	if !ok || !token.Valid {
		return accessIdentity{}, ErrInvalidToken
	}

	orgRole := strings.TrimSpace(claims.OrgRole)
	if claims.Subject == "" ||
		claims.SessionID == uuid.Nil ||
		claims.OrgID == uuid.Nil ||
		orgRole == "" {
		return accessIdentity{}, ErrInvalidToken
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return accessIdentity{}, ErrInvalidToken
	}

	for _, role := range claims.Roles {
		if !strings.HasPrefix(role, "authara:") {
			return accessIdentity{}, ErrInvalidRoleNamespace
		}
	}

	return accessIdentity{
		UserID:           userID,
		OrganizationID:   claims.OrgID,
		OrganizationRole: orgRole,
		Roles:            claims.Roles,
	}, nil
}

func (v *verifier) keyFunc(t *jwt.Token) (any, error) {
	kid, ok := t.Header["kid"].(string)
	if !ok {
		return nil, ErrInvalidToken
	}

	key, ok := v.keys[kid]
	if !ok {
		return nil, ErrInvalidToken
	}

	return key, nil
}
