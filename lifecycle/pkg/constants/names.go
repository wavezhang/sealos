/*
Copyright 2026 sealos.

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

package constants

import (
	"fmt"
	"regexp"
)

// clusterNameRe follows the Kubernetes DNS-1123 label rules. Cluster names
// become path segments and shell arguments, so anything outside this set is
// rejected instead of being escaped.
var clusterNameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// ValidateClusterName rejects empty or unsafe cluster names.
func ValidateClusterName(name string) error {
	if name == "" {
		return fmt.Errorf("cluster name cannot be empty")
	}
	if !clusterNameRe.MatchString(name) {
		return fmt.Errorf("invalid cluster name %q: must match %s", name, clusterNameRe.String())
	}
	return nil
}
