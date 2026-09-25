package domain

import "context"

// SurvivingBackendIDs answers one custody question with ONE backend List
// call at call time: which backend snapshot ids does the vault hold
// right now. It is the query behind forget's last-recovery-copy guard
// (Wave 5, defect E11): a catalog row is not custody — a row whose
// backend copy was already forgotten (and whose row survived) must not
// be counted as a surviving recovery copy. Only ids the CURRENT list
// returns survive.
//
// The returned map is keyed by the store's opaque BackendID, exactly as
// List reported it — no shortening, no case folding.
func SurvivingBackendIDs(ctx context.Context, store SnapshotStore, repoDir, passfile string) (map[string]bool, error) {
	refs, err := store.List(ctx, repoDir, passfile)
	if err != nil {
		return nil, err
	}
	surviving := make(map[string]bool, len(refs))
	for _, r := range refs {
		surviving[r.BackendID] = true
	}
	return surviving, nil
}
