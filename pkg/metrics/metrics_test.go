// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package metrics_test

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/gustinn/talos-kms/pkg/metrics"
	"github.com/gustinn/talos-kms/pkg/server"
)

func TestRecordRequestCounts(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	r := metrics.New(reg)

	r.RecordRequest(server.OpSeal, server.OutcomeSuccess, 10*time.Millisecond)
	r.RecordRequest(server.OpUnseal, server.OutcomeAuthFailure, 5*time.Millisecond)
	r.RecordRequest(server.OpUnseal, server.OutcomeAuthFailure, 5*time.Millisecond)

	want := `
# HELP kms_requests_total Total number of KMS requests by operation and outcome.
# TYPE kms_requests_total counter
kms_requests_total{operation="seal",outcome="success"} 1
kms_requests_total{operation="unseal",outcome="auth_failure"} 2
`

	require.NoError(t, testutil.CollectAndCompare(
		collectorOf(t, reg), strings.NewReader(want), "kms_requests_total"))
}

func TestDurationObserved(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	r := metrics.New(reg)

	r.RecordRequest(server.OpSeal, server.OutcomeSuccess, 10*time.Millisecond)

	count, err := testutil.GatherAndCount(reg, "kms_request_duration_seconds")
	require.NoError(t, err)
	require.Positive(t, count)
}

// collectorOf adapts a Gatherer-backed registry to a Collector for
// CollectAndCompare, which expects a Collector. The registry implements both.
func collectorOf(t *testing.T, reg *prometheus.Registry) prometheus.Collector {
	t.Helper()

	return reg
}
