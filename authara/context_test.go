package authara

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestOrganizationContext(t *testing.T) {
	orgID := uuid.New()
	ctx := withAccessIdentity(context.Background(), accessIdentity{
		UserID:           uuid.New(),
		OrganizationID:   orgID,
		OrganizationRole: "owner",
		Roles:            []string{"authara:user"},
	})

	gotOrgID, ok := OrganizationIDFromContext(ctx)
	if !ok || gotOrgID != orgID {
		t.Fatalf("expected organization ID %v, got %v (ok=%v)", orgID, gotOrgID, ok)
	}
	gotRole, ok := OrganizationRoleFromContext(ctx)
	if !ok || gotRole != "owner" {
		t.Fatalf("expected organization role owner, got %q (ok=%v)", gotRole, ok)
	}
}
