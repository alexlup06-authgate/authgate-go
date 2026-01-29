package authgate

import (
	"context"

	"github.com/google/uuid"
)

type userIDKeyType struct{}
type rolesKeyType struct{}

var userIDKey = userIDKeyType{}
var rolesKey = rolesKeyType{}

func withUserID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey, id)
}

func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	return id, ok
}

func IsAuthenticated(ctx context.Context) bool {
	_, ok := UserIDFromContext(ctx)
	return ok
}

func withRoles(ctx context.Context, roles []string) context.Context {
	return context.WithValue(ctx, rolesKey, roles)
}

func RolesFromContext(ctx context.Context) ([]string, bool) {
	roles, ok := ctx.Value(rolesKey).([]string)
	return roles, ok
}
