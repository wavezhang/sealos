/*
Copyright 2023 cuisongliu@qq.com.

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

package http

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestWaitUntilEndpointAlive(t *testing.T) {
	originalClient := DefaultClient
	t.Cleanup(func() {
		DefaultClient = originalClient
	})

	type args struct {
		ctx      context.Context
		endpoint string
	}
	tests := []struct {
		name       string
		args       args
		statusCode int
		wantErr    bool
	}{
		{
			name:       "ok response",
			args:       args{},
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "unauthorized response",
			args:       args{},
			statusCode: http.StatusUnauthorized,
			wantErr:    false,
		},
		{
			name:       "unexpected response",
			args:       args{},
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DefaultClient = &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path != "/v2/" {
						t.Fatalf("unexpected path: %s", r.URL.Path)
					}
					return &http.Response{
						StatusCode: tt.statusCode,
						Body:       io.NopCloser(http.NoBody),
						Header:     make(http.Header),
					}, nil
				}),
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			tt.args.ctx = ctx
			tt.args.endpoint = "http://registry.example.com"

			if err := WaitUntilEndpointAlive(
				tt.args.ctx,
				tt.args.endpoint,
			); (err != nil) != tt.wantErr {
				t.Errorf("WaitUntilEndpointAlive() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsLoopbackAddress(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:5000", true},
		{"localhost:5050", true},
		{"LOCALHOST", true},
		{"[::1]:5000", true},
		{"http://127.0.0.1:55304/", true},
		{"https://localhost:443", true},
		{"127.0.0.2:5000", true},
		{"registry.example.com:5000", false},
		{"192.168.1.10:5000", false},
		{"10.0.0.1", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsLoopbackAddress(tt.addr); got != tt.want {
			t.Errorf("IsLoopbackAddress(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestIsSealosManagedRegistry(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"sealos.hub:5000", true},
		{"SEALOS.HUB", true},
		{"http://sealos.hub:5000/", true},
		{"10.1.0.85:5000", false},
		{"sealos.hub.example.com:5000", false},
		{"registry.example.com:5000", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsSealosManagedRegistry(tt.addr); got != tt.want {
			t.Errorf("IsSealosManagedRegistry(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}
