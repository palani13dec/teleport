/*
Copyright 2019 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"
)

var boringPath = "crypto/internal/boring"

// IsBoringBinary checks if the binary was compiled with BoringCrypto.
func IsBoringBinary() bool {
	// Check the package name for one of the boring primitives.
	hash := sha256.New()
	if reflect.TypeOf(hash).Elem().PkgPath() != boringPath {
		return false
	}

	return true
}
