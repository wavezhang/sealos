package v1

import (
	"context"
	"strings"
	"testing"

	netv1 "k8s.io/api/networking/v1"
)

func TestIngressValidator_checkHosts(t *testing.T) {
	tests := []struct {
		name    string
		ingress *netv1.Ingress
		wantErr bool
	}{
		{
			name: "plain hosts pass",
			ingress: &netv1.Ingress{
				Spec: netv1.IngressSpec{
					Rules: []netv1.IngressRule{{Host: "app.example.com"}},
					TLS:   []netv1.IngressTLS{{Hosts: []string{"app.example.com"}}},
				},
			},
			wantErr: false,
		},
		{
			name: "wildcard rule host is rejected",
			ingress: &netv1.Ingress{
				Spec: netv1.IngressSpec{
					Rules: []netv1.IngressRule{{Host: "*.cloud.sealos.io"}},
				},
			},
			wantErr: true,
		},
		{
			name: "wildcard tls host is rejected",
			ingress: &netv1.Ingress{
				Spec: netv1.IngressSpec{
					Rules: []netv1.IngressRule{{Host: "app.example.com"}},
					TLS:   []netv1.IngressTLS{{Hosts: []string{"*.example.com"}}},
				},
			},
			wantErr: true,
		},
	}

	v := &IngressValidator{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.checkHosts(tt.ingress)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil, got %v", err)
			}
			if tt.wantErr && !strings.HasPrefix(err.Error(), "40304:") {
				t.Fatalf("expected error code prefix %q, got %q", "40304:", err.Error())
			}
		})
	}
}

func TestHostsOverlap(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "same host", a: "app.example.com", b: "app.example.com", want: true},
		{name: "case and trailing dot", a: "App.Example.Com.", b: "app.example.com", want: true},
		{name: "label boundary differs", a: "evilsealos.io", b: "sealos.io", want: false},
		{name: "parent does not overlap child", a: "example.com", b: "a.example.com", want: false},
		{name: "wildcard covers subdomain", a: "*.example.com", b: "a.example.com", want: true},
		{name: "wildcard does not cover apex", a: "*.example.com", b: "example.com", want: false},
		{name: "empty host", a: "", b: "example.com", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hostsOverlap(tt.a, tt.b); got != tt.want {
				t.Fatalf("hostsOverlap(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestIngressValidator_checkForbiddenDomainSuffix(t *testing.T) {
	tests := []struct {
		name      string
		deny      DomainList
		host      string
		wantError bool
	}{
		{
			name:      "empty deny list passes",
			deny:      nil,
			host:      "a.example.com",
			wantError: false,
		},
		{
			name:      "subdomain is denied",
			deny:      DomainList{"example.com"},
			host:      "a.example.com",
			wantError: true,
		},
		{
			name:      "apex domain is denied",
			deny:      DomainList{"example.com"},
			host:      "example.com",
			wantError: true,
		},
		{
			name:      "other domain passes",
			deny:      DomainList{"example.com"},
			host:      "a.other.com",
			wantError: false,
		},
		{
			name:      "case and trailing dot are normalized",
			deny:      DomainList{"example.com"},
			host:      "A.Example.Com.",
			wantError: true,
		},
	}

	v := &IngressValidator{}
	i := &netv1.Ingress{
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v.DenyDomains = tt.deny
			rule := &netv1.IngressRule{Host: tt.host}
			err := v.checkDeny(context.Background(), i, rule)
			if tt.wantError && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Fatalf("expected nil, got %v", err)
			}
			if tt.wantError {
				// Ensure error code is correct.
				got := err.Error()
				if !strings.HasPrefix(got, "40303:") {
					t.Fatalf("expected error code prefix %q, got %q", "40303:", got)
				}
			}
		})
	}
}
