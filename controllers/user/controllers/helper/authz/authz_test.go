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

package authz

import (
	"context"
	"fmt"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type fakeAuthorizer struct {
	tokenAllowed  bool
	manageAllowed bool
	deleteAllowed bool
	tokenCalls    int
}

func (f *fakeAuthorizer) CanCreateServiceAccountToken(
	_ context.Context,
	_ Identity,
	_ string,
) (bool, error) {
	f.tokenCalls++
	return f.tokenAllowed, nil
}

func (f *fakeAuthorizer) CanUpdateUser(_ context.Context, _ Identity, _ string) (bool, error) {
	return f.manageAllowed, nil
}

func (f *fakeAuthorizer) CanDeleteUser(_ context.Context, _ Identity, _ string) (bool, error) {
	return f.deleteAllowed, nil
}

func TestOperationRequestDecision(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		identity        Identity
		targetUser      string
		namespace       string
		authorizer      *fakeAuthorizer
		wantAllowed     bool
		wantTokenChecks int
	}{
		{
			name:        "self in own namespace",
			identity:    Identity{Username: ServiceAccountUsername("alice")},
			targetUser:  "alice",
			namespace:   UsersNamespace("alice"),
			authorizer:  &fakeAuthorizer{},
			wantAllowed: true,
		},
		{
			name:        "self in other namespace",
			identity:    Identity{Username: ServiceAccountUsername("alice")},
			targetUser:  "alice",
			namespace:   UsersNamespace("bob"),
			authorizer:  &fakeAuthorizer{},
			wantAllowed: false,
		},
		{
			name:            "workspace manager with token permission",
			identity:        Identity{Username: "system:serviceaccount:desktop:desktop"},
			targetUser:      "bob",
			namespace:       UsersNamespace("alice"),
			authorizer:      &fakeAuthorizer{tokenAllowed: true},
			wantAllowed:     true,
			wantTokenChecks: 1,
		},
		{
			name:            "user manager without token permission",
			identity:        Identity{Username: "system:serviceaccount:sealos-system:desktop-frontend"},
			targetUser:      "bob",
			namespace:       UsersNamespace("alice"),
			authorizer:      &fakeAuthorizer{manageAllowed: true},
			wantAllowed:     true,
			wantTokenChecks: 0,
		},
		{
			name:            "caller without token permission",
			identity:        Identity{Username: "system:serviceaccount:desktop:desktop"},
			targetUser:      "bob",
			namespace:       UsersNamespace("alice"),
			authorizer:      &fakeAuthorizer{},
			wantAllowed:     false,
			wantTokenChecks: 1,
		},
		{
			name:        "arbitrary namespace",
			identity:    Identity{Username: "system:serviceaccount:desktop:desktop"},
			targetUser:  "bob",
			namespace:   "kube-system",
			authorizer:  &fakeAuthorizer{tokenAllowed: true},
			wantAllowed: false,
		},
		{
			name:        "invalid target user",
			identity:    Identity{Username: "system:serviceaccount:desktop:desktop"},
			targetUser:  "../bob",
			namespace:   UsersNamespace("alice"),
			authorizer:  &fakeAuthorizer{tokenAllowed: true},
			wantAllowed: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			allowed, reason, err := OperationRequestDecision(
				context.Background(),
				tt.authorizer,
				tt.identity,
				tt.targetUser,
				tt.namespace,
			)
			if err != nil {
				t.Fatalf("OperationRequestDecision returned error: %v", err)
			}
			if allowed != tt.wantAllowed {
				t.Fatalf("allowed = %v, want %v (reason %q)", allowed, tt.wantAllowed, reason)
			}
			if !allowed && reason == "" {
				t.Fatal("denied decision must include a reason")
			}
			if tt.authorizer.tokenCalls != tt.wantTokenChecks {
				t.Fatalf("token checks = %d, want %d", tt.authorizer.tokenCalls, tt.wantTokenChecks)
			}
		})
	}
}

func TestDeleteRequestDecision(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		identity    Identity
		authorizer  *fakeAuthorizer
		wantAllowed bool
	}{
		{
			name:        "target user deletes itself",
			identity:    Identity{Username: ServiceAccountUsername("alice")},
			authorizer:  &fakeAuthorizer{},
			wantAllowed: true,
		},
		{
			name:        "admin with user delete permission",
			identity:    Identity{Username: "system:serviceaccount:admin:admin"},
			authorizer:  &fakeAuthorizer{deleteAllowed: true},
			wantAllowed: true,
		},
		{
			name:        "caller with only user update permission",
			identity:    Identity{Username: "system:serviceaccount:desktop:desktop"},
			authorizer:  &fakeAuthorizer{manageAllowed: true},
			wantAllowed: false,
		},
		{
			name:        "caller without user delete permission",
			identity:    Identity{Username: "system:serviceaccount:desktop:desktop"},
			authorizer:  &fakeAuthorizer{},
			wantAllowed: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			allowed, reason, err := DeleteRequestDecision(
				context.Background(),
				tt.authorizer,
				tt.identity,
				"alice",
			)
			if err != nil {
				t.Fatalf("DeleteRequestDecision returned error: %v", err)
			}
			if allowed != tt.wantAllowed {
				t.Fatalf("allowed = %v, want %v (reason %q)", allowed, tt.wantAllowed, reason)
			}
			if !allowed && reason == "" {
				t.Fatal("denied decision must include a reason")
			}
		})
	}
}

func TestClientAuthorizerBuildsSubjectAccessReview(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	if err := authorizationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("add authorization scheme: %v", err)
	}
	var captured *authorizationv1.SubjectAccessReview
	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(
				_ context.Context,
				_ client.WithWatch,
				obj client.Object,
				_ ...client.CreateOption,
			) error {
				review, ok := obj.(*authorizationv1.SubjectAccessReview)
				if !ok {
					return fmt.Errorf("unexpected object %T", obj)
				}
				captured = review.DeepCopy()
				review.Status.Allowed = true
				return nil
			},
		}).
		Build()

	authorizer := NewClientAuthorizer(cli)
	allowed, err := authorizer.CanCreateServiceAccountToken(
		context.Background(),
		Identity{Username: "system:serviceaccount:user-system:alice", Groups: []string{"g"}},
		"ns-alice",
	)
	if err != nil {
		t.Fatalf("CanCreateServiceAccountToken: %v", err)
	}
	if !allowed {
		t.Fatal("expected allowed result")
	}
	if captured == nil {
		t.Fatal("subject access review was not created")
	}
	attributes := captured.Spec.ResourceAttributes
	if captured.Spec.User != "system:serviceaccount:user-system:alice" ||
		len(captured.Spec.Groups) != 1 ||
		attributes == nil ||
		attributes.Verb != "create" ||
		attributes.Resource != "serviceaccounts" ||
		attributes.Subresource != "token" ||
		attributes.Namespace != "ns-alice" {
		t.Fatalf("unexpected subject access review: %#v", captured)
	}
}
