package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"ebb/internal/domain"
)

// InventoryFile is the saved-inventory interchange format consumed by
// `ebb plan --from-inventory` (the wave-A integration seam; wave B
// replaces it with the live scanner). Decoding is strict: unknown
// fields are rejected so a misspelled safety-relevant field cannot
// silently vanish (Foundation §16.1).
type InventoryFile struct {
	SchemaVersion int                     `json:"schema_version"`
	Summary       domain.InventorySummary `json:"summary"`
	Entries       []domain.Entry          `json:"entries"`
	Volume        domain.VolumeUsage      `json:"volume,omitempty"`
}

// inventorySchema is the only accepted schema version of the file.
const inventorySchema = 1

// LoadInventory reads and strictly decodes a saved inventory JSON file.
func LoadInventory(path string) (InventoryFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return InventoryFile{}, fmt.Errorf("read %s: %w", path, err)
	}
	var inv InventoryFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&inv); err != nil {
		return InventoryFile{}, fmt.Errorf("%s: %w", path, err)
	}
	if inv.SchemaVersion != inventorySchema {
		return InventoryFile{}, fmt.Errorf("%s: schema_version must be %d, got %d",
			path, inventorySchema, inv.SchemaVersion)
	}
	return inv, nil
}
