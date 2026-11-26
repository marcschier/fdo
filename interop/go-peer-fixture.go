// Copyright (c) marcschier. Licensed under the MIT License.

package main

import fdo "github.com/fido-device-onboard/go-fdo"

func init() {
	// This fixture does not negotiate vendor capabilities. Use an empty CBOR array, not null.
	fdo.GlobalCapabilityFlags.VendorUnique = []string{}
}
