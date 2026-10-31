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

// Package authz centralizes the SubjectAccessReview checks used by the user
// controller webhooks and reconcilers. It intentionally only depends on the
// Kubernetes API packages so that both api/v1 and controllers can use it
// without an import cycle.
package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// UserSystemNamespace hosts the per-user service accounts and the
	// OperationRequest/DeleteRequest objects.
	UserSystemNamespace = "user-system"
	// UsersNamespacePrefix is the prefix of the namespace owned by a user.
	UsersNamespacePrefix = "ns-"
)

// Identity is the authenticated caller of an admission request.
type Identity struct {
	Username string
	Groups   []string
}

// Authorizer answers whether an identity may perform an operation.
type Authorizer interface {
	CanCreateServiceAccountToken(
		ctx context.Context,
		identity Identity,
		namespace string,
	) (bool, error)
	CanUpdateUser(ctx context.Context, identity Identity, user string) (bool, error)
	CanDeleteUser(ctx context.Context, identity Identity, user string) (bool, error)
}

// ClientAuthorizer performs SubjectAccessReview requests with the controller
// client.
type ClientAuthorizer struct {
	Client client.Client
}

func NewClientAuthorizer(c client.Client) *ClientAuthorizer {
	return &ClientAuthorizer{Client: c}
}

func (a *ClientAuthorizer) CanCreateServiceAccountToken(
	ctx context.Context,
	identity Identity,
	namespace string,
) (bool, error) {
	return a.allowed(ctx, identity, &authorizationv1.ResourceAttributes{
		Namespace:   namespace,
		Verb:        "create",
		Group:       "",
		Resource:    "serviceaccounts",
		Subresource: "token",
	})
}

func (a *ClientAuthorizer) CanUpdateUser(
	ctx context.Context,
	identity Identity,
	user string,
) (bool, error) {
	return a.allowed(ctx, identity, &authorizationv1.ResourceAttributes{
		Verb:     "update",
		Group:    "user.sealos.io",
		Resource: "users",
		Name:     user,
	})
}

func (a *ClientAuthorizer) CanDeleteUser(
	ctx context.Context,
	identity Identity,
	user string,
) (bool, error) {
	return a.allowed(ctx, identity, &authorizationv1.ResourceAttributes{
		Verb:     "delete",
		Group:    "user.sealos.io",
		Resource: "users",
		Name:     user,
	})
}

func (a *ClientAuthorizer) allowed(
	ctx context.Context,
	identity Identity,
	attributes *authorizationv1.ResourceAttributes,
) (bool, error) {
	if a == nil || a.Client == nil {
		return false, errors.New("authorization client is not configured")
	}
	if identity.Username == "" {
		return false, nil
	}
	review := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:               identity.Username,
			Groups:             identity.Groups,
			ResourceAttributes: attributes,
		},
	}
	if err := a.Client.Create(ctx, review); err != nil {
		return false, fmt.Errorf("create subject access review: %w", err)
	}
	return review.Status.Allowed, nil
}

// ServiceAccountUsername returns the Kubernetes username of the service
// account that represents a sealos user.
func ServiceAccountUsername(user string) string {
	return "system:serviceaccount:" + UserSystemNamespace + ":" + user
}

// UsersNamespace returns the namespace owned by a user.
func UsersNamespace(user string) string {
	return UsersNamespacePrefix + user
}

// ValidateUserName checks that a user name can safely be used as an object and
// namespace name.
func ValidateUserName(user string) error {
	if user == "" {
		return errors.New("user must not be empty")
	}
	if errs := validation.IsDNS1123Label(user); len(errs) > 0 {
		return fmt.Errorf("invalid user %q: %s", user, strings.Join(errs, ", "))
	}
	return nil
}

// ValidateUsersNamespace checks that namespace is a per-user workspace
// namespace (ns-<user>). Any other namespace is rejected so that requests can
// never target arbitrary cluster namespaces.
func ValidateUsersNamespace(namespace string) error {
	if !strings.HasPrefix(namespace, UsersNamespacePrefix) {
		return fmt.Errorf("namespace %q is not a user workspace namespace", namespace)
	}
	return ValidateUserName(strings.TrimPrefix(namespace, UsersNamespacePrefix))
}

// OperationRequestDecision decides whether identity may create an
// OperationRequest that grants a role to targetUser in namespace.
//
// The request may be created by:
//   - the target user itself, for its own workspace namespace only;
//   - a trusted controller that may update the User object (this is how the
//     desktop backend creates team management requests on behalf of users);
//   - an identity that may mint service account tokens in the namespace, which
//     already lets it act with the workspace's permissions.
//
// Any other caller, including the target user for a foreign namespace, is
// denied.
func OperationRequestDecision(
	ctx context.Context,
	authorizer Authorizer,
	identity Identity,
	targetUser, namespace string,
) (bool, string, error) {
	if err := ValidateUserName(targetUser); err != nil {
		return false, err.Error(), nil
	}
	if err := ValidateUsersNamespace(namespace); err != nil {
		return false, err.Error(), nil
	}
	if identity.Username == ServiceAccountUsername(targetUser) {
		if namespace != UsersNamespace(targetUser) {
			return false, fmt.Sprintf(
				"user %s may only operate on its own namespace %s",
				targetUser,
				UsersNamespace(targetUser),
			), nil
		}
		return true, "", nil
	}
	manager, err := authorizer.CanUpdateUser(ctx, identity, targetUser)
	if err != nil {
		return false, "", err
	}
	if manager {
		return true, "", nil
	}
	allowed, err := authorizer.CanCreateServiceAccountToken(ctx, identity, namespace)
	if err != nil {
		return false, "", err
	}
	if allowed {
		return true, "", nil
	}
	return false, fmt.Sprintf(
		"requester %s is neither the target user, a user manager, nor allowed to create service account tokens in namespace %s",
		identity.Username,
		namespace,
	), nil
}

// DeleteRequestDecision decides whether identity may delete targetUser and its
// workspace namespace. Only the target user itself or an identity allowed to
// delete the User object is accepted; the namespace cleanup is performed by
// the controller with its own service account.
func DeleteRequestDecision(
	ctx context.Context,
	authorizer Authorizer,
	identity Identity,
	targetUser string,
) (bool, string, error) {
	if err := ValidateUserName(targetUser); err != nil {
		return false, err.Error(), nil
	}
	if identity.Username == ServiceAccountUsername(targetUser) {
		return true, "", nil
	}
	userAllowed, err := authorizer.CanDeleteUser(ctx, identity, targetUser)
	if err != nil {
		return false, "", err
	}
	if !userAllowed {
		return false, fmt.Sprintf(
			"requester %s is neither the target user nor allowed to delete user %s",
			identity.Username,
			targetUser,
		), nil
	}
	return true, "", nil
}
