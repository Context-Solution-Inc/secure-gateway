package memory_test

import (
	"testing"

	"github.com/lley154/secure-gateway/internal/authstore"
	"github.com/lley154/secure-gateway/internal/authstore/memory"
	"github.com/lley154/secure-gateway/internal/authstore/storetest"
)

func TestMemoryStoreConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) authstore.Store { return memory.New() })
}
