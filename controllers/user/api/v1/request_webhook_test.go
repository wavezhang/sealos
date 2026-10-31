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

import (
	"context"
	"testing"

	"github.com/labring/sealos/controllers/user/controllers/helper/authz"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type allowAuthorizer struct {
	allowToken  bool
	allowManage bool
	allowDelete bool
}

func (a allowAuthorizer) CanCreateServiceAccountToken(
	_ context.Context,
	_ authz.Identity,
	_ string,
) (bool, error) {
	return a.allowToken, nil
}

func (a allowAuthorizer) CanUpdateUser(_ context.Context, _ authz.Identity, _ string) (bool, error) {
	return a.allowManage, nil
}

func (a allowAuthorizer) CanDeleteUser(_ context.Context, _ authz.Identity, _ string) (bool, error) {
	return a.allowDelete, nil
}

func admissionContext(
	t *testing.T,
	operation admissionv1.Operation,
	username string,
) context.Context {
	t.Helper()
	return admission.NewContextWithRequest(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: operation,
			UserInfo:  authenticationv1.UserInfo{Username: username},
		},
	})
}

func testClient(t *testing.T) *fake.ClientBuilder {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("add user scheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(scheme)
}

func TestOperationRequestWebhookRecordsAuthenticatedCreator(t *testing.T) {
	t.Parallel()
	request := &Operationrequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "request",
			Namespace: authz.UserSystemNamespace,
			Annotations: map[string]string{
				UserAnnotationCreatorKey: "forged",
			},
		},
		Spec: OperationrequestSpec{
			Namespace: authz.UsersNamespace("alice"),
			User:      "alice",
			Role:      OwnerRoleType,
			Action:    Grant,
		},
	}
	mutator := ReqMutator{}
	if err := mutator.Default(
		admissionContext(t, admissionv1.Create, authz.ServiceAccountUsername("alice")),
		request,
	); err != nil {
		t.Fatalf("mutate request: %v", err)
	}
	if creator := request.Annotations[UserAnnotationCreatorKey]; creator != authz.ServiceAccountUsername("alice") {
		t.Fatalf("creator = %q, want authenticated caller", creator)
	}
}

func TestOperationRequestWebhookCreateAuthorization(t *testing.T) {
	t.Parallel()
	request := &Operationrequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "request",
			Namespace: authz.UserSystemNamespace,
		},
		Spec: OperationrequestSpec{
			Namespace: authz.UsersNamespace("alice"),
			User:      "bob",
			Role:      DeveloperRoleType,
			Action:    Grant,
		},
	}

	t.Run("self in own namespace", func(t *testing.T) {
		t.Parallel()
		selfRequest := request.DeepCopy()
		selfRequest.Spec.User = "alice"
		validator := ReqValidator{
			Client:     testClient(t).Build(),
			Authorizer: allowAuthorizer{},
		}
		if _, err := validator.ValidateCreate(
			admissionContext(t, admissionv1.Create, authz.ServiceAccountUsername("alice")),
			selfRequest,
		); err != nil {
			t.Fatalf("self-service request was rejected: %v", err)
		}
	})

	t.Run("caller without token permission", func(t *testing.T) {
		t.Parallel()
		validator := ReqValidator{
			Client:     testClient(t).Build(),
			Authorizer: allowAuthorizer{},
		}
		_, err := validator.ValidateCreate(
			admissionContext(t, admissionv1.Create, "system:serviceaccount:desktop:desktop"),
			request,
		)
		if err == nil {
			t.Fatal("unauthorized caller was accepted")
		}
	})

	t.Run("workspace manager with token permission", func(t *testing.T) {
		t.Parallel()
		validator := ReqValidator{
			Client:     testClient(t).Build(),
			Authorizer: allowAuthorizer{allowToken: true},
		}
		if _, err := validator.ValidateCreate(
			admissionContext(t, admissionv1.Create, authz.ServiceAccountUsername("alice")),
			request,
		); err != nil {
			t.Fatalf("authorized caller was rejected: %v", err)
		}
	})

	t.Run("missing admission identity", func(t *testing.T) {
		t.Parallel()
		validator := ReqValidator{
			Client:     testClient(t).Build(),
			Authorizer: allowAuthorizer{allowToken: true},
		}
		if _, err := validator.ValidateCreate(context.Background(), request); err == nil {
			t.Fatal("request without an admission caller was accepted")
		}
	})
}

func TestOperationRequestWebhookRejectsCreatorChange(t *testing.T) {
	t.Parallel()
	oldRequest := &Operationrequest{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{UserAnnotationCreatorKey: "alice"},
		},
		Spec: OperationrequestSpec{
			Namespace: authz.UsersNamespace("alice"),
			User:      "bob",
			Role:      DeveloperRoleType,
			Action:    Grant,
		},
	}
	newRequest := oldRequest.DeepCopy()
	newRequest.Annotations[UserAnnotationCreatorKey] = "mallory"

	validator := ReqValidator{Client: testClient(t).Build(), Authorizer: allowAuthorizer{}}
	if _, err := validator.ValidateUpdate(
		admissionContext(t, admissionv1.Update, "mallory"),
		oldRequest,
		newRequest,
	); err == nil {
		t.Fatal("creator annotation change was accepted")
	}
}

func TestDeleteRequestWebhookCreateAuthorization(t *testing.T) {
	t.Parallel()
	request := &DeleteRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "delete-alice"},
		Spec:       DeleteRequestSpec{User: "alice"},
	}

	tests := []struct {
		name        string
		username    string
		authorizer  allowAuthorizer
		wantAllowed bool
	}{
		{
			name:        "target user deletes itself",
			username:    authz.ServiceAccountUsername("alice"),
			wantAllowed: true,
		},
		{
			name:        "backend with user delete permission",
			username:    "system:serviceaccount:sealos-system:desktop-frontend",
			authorizer:  allowAuthorizer{allowDelete: true},
			wantAllowed: true,
		},
		{
			name:        "caller without user delete permission",
			username:    "system:serviceaccount:ns-alice:default",
			authorizer:  allowAuthorizer{},
			wantAllowed: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			validator := DeleteRequestValidator{
				Client:     testClient(t).Build(),
				Authorizer: tt.authorizer,
			}
			_, err := validator.ValidateCreate(
				admissionContext(t, admissionv1.Create, tt.username),
				request,
			)
			if tt.wantAllowed && err != nil {
				t.Fatalf("authorized request was rejected: %v", err)
			}
			if !tt.wantAllowed && err == nil {
				t.Fatal("unauthorized request was accepted")
			}
		})
	}
}

func TestDeleteRequestWebhookRejectsCreatorChange(t *testing.T) {
	t.Parallel()
	oldRequest := &DeleteRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "delete-alice",
			Annotations: map[string]string{UserAnnotationCreatorKey: "alice"},
		},
		Spec: DeleteRequestSpec{User: "alice"},
	}
	newRequest := oldRequest.DeepCopy()
	newRequest.Annotations[UserAnnotationCreatorKey] = "mallory"

	validator := DeleteRequestValidator{
		Client:     testClient(t).Build(),
		Authorizer: allowAuthorizer{allowDelete: true},
	}
	if _, err := validator.ValidateUpdate(
		admissionContext(t, admissionv1.Update, "mallory"),
		oldRequest,
		newRequest,
	); err == nil {
		t.Fatal("creator annotation change was accepted")
	}
}
