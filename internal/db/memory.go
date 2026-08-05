package db

import (
	"encoding/json"
	"fmt"
)

func newMemoryStore(payload []byte) (*Store, error) {
	s := &Store{state: newState()}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &s.state); err != nil {
			return nil, fmt.Errorf("decode postgres state: %w", err)
		}
	}
	s.normalize()
	return s, nil
}
