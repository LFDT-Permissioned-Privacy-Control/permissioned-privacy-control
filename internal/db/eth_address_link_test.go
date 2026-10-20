package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupEthLinkDB creates a DB instance with migrations applied and registers cleanup.
func setupEthLinkDB(t *testing.T) *DB {
	t.Helper()
	database := setupTestDB(t)
	t.Cleanup(func() { cleanupTestDB(t, database) })
	return database
}

// ---------------------------------------------------------------------------
// TestSystemLinkEthAddress
// ---------------------------------------------------------------------------

func TestSystemLinkEthAddress(t *testing.T) {
	database := setupEthLinkDB(t)
	ctx := context.Background()

	t.Run("creates row with link_type system", func(t *testing.T) {
		did := "did:privado:sys1"
		addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

		err := database.SystemLinkEthAddress(ctx, did, addr)
		require.NoError(t, err)

		links, err := database.GetEthAddressesByDID(ctx, did)
		require.NoError(t, err)
		require.Len(t, links, 1)
		assert.Equal(t, addr, links[0].EthAddress)
		assert.Equal(t, "system", links[0].LinkType)
	})

	t.Run("idempotent same DID and address", func(t *testing.T) {
		did := "did:privado:sys_idem"
		addr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

		require.NoError(t, database.SystemLinkEthAddress(ctx, did, addr))
		require.NoError(t, database.SystemLinkEthAddress(ctx, did, addr))

		links, err := database.GetEthAddressesByDID(ctx, did)
		require.NoError(t, err)
		assert.Len(t, links, 1, "second call should be a no-op")
	})

	t.Run("lowercases the address", func(t *testing.T) {
		did := "did:privado:sys_lower"
		mixed := "0xAbCdEf0000000000000000000000000000000001"

		require.NoError(t, database.SystemLinkEthAddress(ctx, did, mixed))

		links, err := database.GetEthAddressesByDID(ctx, did)
		require.NoError(t, err)
		require.Len(t, links, 1)
		assert.Equal(t, "0xabcdef0000000000000000000000000000000001", links[0].EthAddress)
	})

	t.Run("empty DID is a no-op", func(t *testing.T) {
		err := database.SystemLinkEthAddress(ctx, "", "0x1111111111111111111111111111111111111111")
		require.NoError(t, err)
	})

	t.Run("empty address is a no-op", func(t *testing.T) {
		err := database.SystemLinkEthAddress(ctx, "did:privado:sys_empty_addr", "")
		require.NoError(t, err)
	})

	t.Run("GetLinkedEthAddresses returns system-linked address", func(t *testing.T) {
		did := "did:privado:sys_get_linked"
		addr := "0xcccccccccccccccccccccccccccccccccccccccc"

		require.NoError(t, database.SystemLinkEthAddress(ctx, did, addr))

		addrs, err := database.GetLinkedEthAddresses(ctx, did)
		require.NoError(t, err)
		require.Len(t, addrs, 1)
		assert.Equal(t, addr, addrs[0])
	})
}

// ---------------------------------------------------------------------------
// TestGetDIDsByEthAddress
// ---------------------------------------------------------------------------

func TestGetDIDsByEthAddress(t *testing.T) {
	database := setupEthLinkDB(t)
	ctx := context.Background()

	t.Run("returns empty slice for unknown address", func(t *testing.T) {
		dids, err := database.GetDIDsByEthAddress(ctx, "0x0000000000000000000000000000000000000000")
		require.NoError(t, err)
		assert.Empty(t, dids)
	})

	t.Run("returns single DID for a single link", func(t *testing.T) {
		did := "did:privado:getdids_single"
		addr := "0xdddddddddddddddddddddddddddddddddddddd"
		require.NoError(t, database.LinkEthAddress(ctx, did, addr, "sig", "hash"))

		dids, err := database.GetDIDsByEthAddress(ctx, addr)
		require.NoError(t, err)
		require.Len(t, dids, 1)
		assert.Equal(t, did, dids[0])
	})

	t.Run("returns multiple DIDs when two different DIDs link same address", func(t *testing.T) {
		didUser := "did:privado:getdids_user"
		didSystem := "did:privado:getdids_system"
		addr := "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

		require.NoError(t, database.LinkEthAddress(ctx, didUser, addr, "sig", "hash"))
		require.NoError(t, database.SystemLinkEthAddress(ctx, didSystem, addr))

		dids, err := database.GetDIDsByEthAddress(ctx, addr)
		require.NoError(t, err)
		require.Len(t, dids, 2)
		assert.Contains(t, dids, didUser)
		assert.Contains(t, dids, didSystem)
	})

	t.Run("excludes revoked links", func(t *testing.T) {
		didA := "did:privado:getdids_revA"
		didB := "did:privado:getdids_revB"
		addr := "0xf0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0"

		require.NoError(t, database.LinkEthAddress(ctx, didA, addr, "sigA", "hashA"))
		require.NoError(t, database.LinkEthAddress(ctx, didB, addr, "sigB", "hashB"))

		// Revoke didA's link.
		require.NoError(t, database.RevokeEthAddressLink(ctx, didA, addr))

		dids, err := database.GetDIDsByEthAddress(ctx, addr)
		require.NoError(t, err)
		require.Len(t, dids, 1)
		assert.Equal(t, didB, dids[0])
	})

	t.Run("user-linked DID appears before system-linked DID", func(t *testing.T) {
		didSystem := "did:privado:getdids_order_sys"
		didUser := "did:privado:getdids_order_usr"
		addr := "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

		// System-link first, then user-link second.
		require.NoError(t, database.SystemLinkEthAddress(ctx, didSystem, addr))
		require.NoError(t, database.LinkEthAddress(ctx, didUser, addr, "sig", "hash"))

		dids, err := database.GetDIDsByEthAddress(ctx, addr)
		require.NoError(t, err)
		require.Len(t, dids, 2)
		assert.Equal(t, didUser, dids[0], "user-linked DID should come first")
		assert.Equal(t, didSystem, dids[1], "system-linked DID should come second")
	})
}

// ---------------------------------------------------------------------------
// TestGetAddressLinkCollisions
// ---------------------------------------------------------------------------

func TestGetAddressLinkCollisions(t *testing.T) {
	database := setupEthLinkDB(t)
	ctx := context.Background()

	t.Run("returns empty slice when no collisions exist", func(t *testing.T) {
		collisions, err := database.GetAddressLinkCollisions(ctx)
		require.NoError(t, err)
		assert.Empty(t, collisions)
	})

	t.Run("returns collision when two DIDs link the same address", func(t *testing.T) {
		didA := "did:privado:coll_a"
		didB := "did:privado:coll_b"
		addr := "0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"

		require.NoError(t, database.LinkEthAddress(ctx, didA, addr, "sigA", "hashA"))
		require.NoError(t, database.SystemLinkEthAddress(ctx, didB, addr))

		collisions, err := database.GetAddressLinkCollisions(ctx)
		require.NoError(t, err)
		require.Len(t, collisions, 1)
		assert.Equal(t, addr, collisions[0].EthAddress)
		assert.Len(t, collisions[0].DIDs, 2)
		assert.Contains(t, collisions[0].DIDs, didA)
		assert.Contains(t, collisions[0].DIDs, didB)
		assert.Len(t, collisions[0].LinkTypes, 2)
		assert.Contains(t, collisions[0].LinkTypes, "user")
		assert.Contains(t, collisions[0].LinkTypes, "system")
	})

	t.Run("does NOT return an address linked to only one DID", func(t *testing.T) {
		didSolo := "did:privado:coll_solo"
		addrSolo := "0xc3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"

		require.NoError(t, database.LinkEthAddress(ctx, didSolo, addrSolo, "sig", "hash"))

		collisions, err := database.GetAddressLinkCollisions(ctx)
		require.NoError(t, err)
		for _, c := range collisions {
			assert.NotEqual(t, addrSolo, c.EthAddress, "single-DID address should not appear as collision")
		}
	})

	t.Run("does NOT include revoked links in collision count", func(t *testing.T) {
		didX := "did:privado:coll_rev_x"
		didY := "did:privado:coll_rev_y"
		addr := "0xd4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"

		require.NoError(t, database.LinkEthAddress(ctx, didX, addr, "sigX", "hashX"))
		require.NoError(t, database.LinkEthAddress(ctx, didY, addr, "sigY", "hashY"))

		// Revoke one — bringing active links to 1, which should remove the collision.
		require.NoError(t, database.RevokeEthAddressLink(ctx, didX, addr))

		collisions, err := database.GetAddressLinkCollisions(ctx)
		require.NoError(t, err)
		for _, c := range collisions {
			assert.NotEqual(t, addr, c.EthAddress, "address with one revoked link should not be a collision")
		}
	})
}

// ---------------------------------------------------------------------------
// TestLinkEthAddress_UpdatedBehavior
// ---------------------------------------------------------------------------

func TestLinkEthAddress_UpdatedBehavior(t *testing.T) {
	database := setupEthLinkDB(t)
	ctx := context.Background()

	t.Run("creates row with link_type user", func(t *testing.T) {
		did := "did:privado:link_user"
		addr := "0xe5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"

		require.NoError(t, database.LinkEthAddress(ctx, did, addr, "sig", "hash"))

		links, err := database.GetEthAddressesByDID(ctx, did)
		require.NoError(t, err)
		require.Len(t, links, 1)
		assert.Equal(t, "user", links[0].LinkType)
	})

	t.Run("two different DIDs can user-link the same address", func(t *testing.T) {
		did1 := "did:privado:link_dup1"
		did2 := "did:privado:link_dup2"
		addr := "0xf6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6"

		require.NoError(t, database.LinkEthAddress(ctx, did1, addr, "sig1", "hash1"))
		require.NoError(t, database.LinkEthAddress(ctx, did2, addr, "sig2", "hash2"))

		links1, err := database.GetEthAddressesByDID(ctx, did1)
		require.NoError(t, err)
		assert.Len(t, links1, 1)

		links2, err := database.GetEthAddressesByDID(ctx, did2)
		require.NoError(t, err)
		assert.Len(t, links2, 1)
	})

	t.Run("re-linking own address refreshes signature", func(t *testing.T) {
		did := "did:privado:link_refresh"
		addr := "0xa7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7"

		require.NoError(t, database.LinkEthAddress(ctx, did, addr, "sig1", "hash1"))
		require.NoError(t, database.LinkEthAddress(ctx, did, addr, "sig2", "hash2"))

		links, err := database.GetEthAddressesByDID(ctx, did)
		require.NoError(t, err)
		require.Len(t, links, 1)
		assert.Equal(t, "sig2", links[0].Signature, "signature should be refreshed")
	})

	t.Run("user-linking upgrades system link to user", func(t *testing.T) {
		did := "did:privado:link_upgrade"
		addr := "0xb8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8"

		// First create system link.
		require.NoError(t, database.SystemLinkEthAddress(ctx, did, addr))

		links, err := database.GetEthAddressesByDID(ctx, did)
		require.NoError(t, err)
		require.Len(t, links, 1)
		assert.Equal(t, "system", links[0].LinkType)

		// Now user-link the same address — should upgrade.
		require.NoError(t, database.LinkEthAddress(ctx, did, addr, "sig", "hash"))

		links, err = database.GetEthAddressesByDID(ctx, did)
		require.NoError(t, err)
		require.Len(t, links, 1)
		assert.Equal(t, "user", links[0].LinkType, "link_type should be upgraded to user")
	})

	t.Run("revoked link returns ErrAddressLinkRevoked", func(t *testing.T) {
		did := "did:privado:link_revoked"
		addr := "0xc9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9"

		require.NoError(t, database.LinkEthAddress(ctx, did, addr, "sig1", "hash1"))
		require.NoError(t, database.RevokeEthAddressLink(ctx, did, addr))

		err := database.LinkEthAddress(ctx, did, addr, "sig2", "hash2")
		require.ErrorIs(t, err, ErrAddressLinkRevoked)
	})
}
