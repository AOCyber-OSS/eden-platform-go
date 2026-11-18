package observability

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestAuthMetrics_RecordLegacyUntypedToken: the counter ops watch to see
// pre-#80 tokens stop arriving, labelled by inferred token_use.
func TestAuthMetrics_RecordLegacyUntypedToken(t *testing.T) {
	m := NewAuthMetrics(prometheus.NewRegistry())
	m.RecordLegacyUntypedToken("refresh")
	m.RecordLegacyUntypedToken("refresh")
	m.RecordLegacyUntypedToken("access")
	if got := testutil.ToFloat64(m.legacyUntypedTokensTotal.WithLabelValues("refresh")); got != 2 {
		t.Errorf("refresh = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.legacyUntypedTokensTotal.WithLabelValues("access")); got != 1 {
		t.Errorf("access = %v, want 1", got)
	}
}
