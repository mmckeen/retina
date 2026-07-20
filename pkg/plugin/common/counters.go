// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package common

// CounterDelta returns how much to add to a cumulative metric given the current
// value and the last-seen value, along with the new last-seen value. A decrease
// is treated as a counter reset (report nothing, adopt the new value).
func CounterDelta(total, last uint64) (add, newLast uint64) {
	if total <= last {
		return 0, total
	}
	return total - last, total
}
