package authgate

import "errors"

var (
	ErrInvalidToken         = errors.New("authgate: invalid access token")
	ErrTokenExpired         = errors.New("authgate: token is expired")
	ErrInvalidRoleNamespace = errors.New("authgate: role namespace is invalid")
)
