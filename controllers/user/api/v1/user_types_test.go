/*
Copyright 2026 labring.

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

package v1

import "testing"

func TestCSRExpirationPolicyBounds(t *testing.T) {
	t.Parallel()
	if MinCSRExpirationSeconds <= 0 {
		t.Fatalf("minimum lifetime = %d, want a positive floor", MinCSRExpirationSeconds)
	}
	if DefaultCSRExpirationSeconds < MinCSRExpirationSeconds ||
		DefaultCSRExpirationSeconds > MaxCSRExpirationSeconds {
		t.Fatalf(
			"default lifetime %d outside [%d, %d]",
			DefaultCSRExpirationSeconds,
			MinCSRExpirationSeconds,
			MaxCSRExpirationSeconds,
		)
	}
	if DefaultCSRExpirationSeconds != 7*24*60*60 {
		t.Fatalf("default lifetime = %d, want 7 days", DefaultCSRExpirationSeconds)
	}
	if MaxCSRExpirationSeconds != 30*24*60*60 {
		t.Fatalf("maximum lifetime = %d, want 30 days", MaxCSRExpirationSeconds)
	}
}

func TestNormalizeCSRExpirationSeconds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value int32
		want  int32
	}{
		{
			name:  "zero uses the default",
			value: 0,
			want:  DefaultCSRExpirationSeconds,
		},
		{
			name:  "negative uses the default",
			value: -1,
			want:  DefaultCSRExpirationSeconds,
		},
		{
			name:  "below floor uses the default",
			value: MinCSRExpirationSeconds - 1,
			want:  DefaultCSRExpirationSeconds,
		},
		{
			name:  "floor is preserved",
			value: MinCSRExpirationSeconds,
			want:  MinCSRExpirationSeconds,
		},
		{
			name:  "short in-range value is preserved",
			value: 7_200,
			want:  7_200,
		},
		{
			name:  "default is preserved",
			value: DefaultCSRExpirationSeconds,
			want:  DefaultCSRExpirationSeconds,
		},
		{
			name:  "below maximum is preserved",
			value: MaxCSRExpirationSeconds - 1,
			want:  MaxCSRExpirationSeconds - 1,
		},
		{
			name:  "maximum is preserved",
			value: MaxCSRExpirationSeconds,
			want:  MaxCSRExpirationSeconds,
		},
		{
			name:  "above maximum is clamped",
			value: MaxCSRExpirationSeconds + 1,
			want:  MaxCSRExpirationSeconds,
		},
		{
			name:  "legacy one billion seconds is clamped",
			value: 1_000_000_000,
			want:  MaxCSRExpirationSeconds,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeCSRExpirationSeconds(tt.value); got != tt.want {
				t.Fatalf(
					"NormalizeCSRExpirationSeconds(%d) = %d, want %d",
					tt.value,
					got,
					tt.want,
				)
			}
		})
	}
}
