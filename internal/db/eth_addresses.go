package db

import (
	"context"
	"fmt"
	"strings"
)

// GetLinkedEthAddresses returns the lowercase ETH addresses linked to a DID.
// This wraps GetEthAddressesByDID, extracting just the address strings.
func (d *DB) GetLinkedEthAddresses(ctx context.Context, did string) ([]string, error) {
	links, err := d.GetEthAddressesByDID(ctx, did)
	if err != nil {
		return nil, err
	}
	addrs := make([]string, len(links))
	for i, l := range links {
		addrs[i] = strings.ToLower(l.EthAddress)
	}
	return addrs, nil
}

// GetOrgIDsForEthAddress returns all organization IDs that the owner of a given
// ETH address belongs to, by joining eth_address_links → users → memberships → groups.
// Returns nil if the address is not linked to any user.
func (d *DB) GetOrgIDsForEthAddress(ctx context.Context, address string) ([]string, error) {
	query := `
		SELECT DISTINCT g.org_id
		FROM eth_address_links eal
		JOIN users u ON u.external_id = eal.did
		JOIN user_memberships um ON um.user_id = u.id
		JOIN groups g ON g.id = um.group_id
		WHERE LOWER(eal.eth_address) = LOWER($1)
		  AND eal.revoked = false
	`
	rows, err := d.conn.QueryContext(ctx, query, address)
	if err != nil {
		return nil, fmt.Errorf("failed to get org IDs for ETH address: %w", err)
	}
	defer rows.Close()

	var orgIDs []string
	for rows.Next() {
		var orgID string
		if err := rows.Scan(&orgID); err != nil {
			return nil, fmt.Errorf("failed to scan org ID: %w", err)
		}
		orgIDs = append(orgIDs, orgID)
	}
	return orgIDs, rows.Err()
}
