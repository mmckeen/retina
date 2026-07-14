// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/* Template */

package endpoint

import (
	"context"
)

// hooks has no OS-facing dependencies to inject on Windows.
type hooks struct{} //nolint:unused // satisfies the shared EndpointWatcher.hooks field; no netlink on windows

func (e *EndpointWatcher) subscribe(_ context.Context) {}

func describeEndpoint(_ interface{}) string { return "" }

func (e *EndpointWatcher) initNewCache() error {
	return nil
}
