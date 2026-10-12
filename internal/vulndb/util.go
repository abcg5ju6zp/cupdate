package vulndb

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/AlexGustafsson/cupdate/internal/httputil"
)

var (
	managersMu sync.Mutex
	managers   = make(map[string]*Manager)
)

// AutoFetchAndOpen returns a read connection to the vulnerability database at
// path, downloading and atomically publishing a new generation when the local
// one is missing or older than maxAge. Workers sharing the same path share a
// single [Manager], so concurrent refreshes result in exactly one generation
// commit.
//
// A nil httpClient disables automatic downloads: the locally published
// generation is opened as-is, and an error is returned on a missing database.
//
// The returned connection stays on the generation published at acquisition
// time even if a refresh switches the active generation meanwhile.
func AutoFetchAndOpen(ctx context.Context, path string, httpClient httputil.Requester, maxAge time.Duration) (*Conn, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	managersMu.Lock()
	manager, ok := managers[absolute]
	if !ok {
		manager, err = newManager(absolute, httpClient, maxAge)
		if err != nil {
			managersMu.Unlock()
			return nil, err
		}
		managers[absolute] = manager
	}
	managersMu.Unlock()

	return manager.Get(ctx)
}
