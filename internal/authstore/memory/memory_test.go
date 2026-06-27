package memory_test

import (
	"testing"

	"github.com/context-solutions-inc/secure-gateway/internal/authstore"
	"github.com/context-solutions-inc/secure-gateway/internal/authstore/memory"
	"github.com/context-solutions-inc/secure-gateway/internal/authstore/storetest"
)

func TestMemoryStoreConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) authstore.Store { return memory.New() })
}
