/*
Copyright 2022 labring.

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
	"errors"
	"fmt"

	"github.com/labring/sealos/controllers/user/controllers/helper/authz"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// log is for logging in this package.
var operationrequestlog = logf.Log.WithName("operationrequest-resource")

func (r *Operationrequest) SetupWebhookWithManager(mgr ctrl.Manager) error {
	m := &ReqMutator{Client: mgr.GetClient()}
	v := &ReqValidator{
		Client:     mgr.GetClient(),
		Authorizer: authz.NewClientAuthorizer(mgr.GetClient()),
	}
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		WithDefaulter(m).
		WithValidator(v).
		Complete()
}

// requesterIdentity returns the authenticated identity of the admission
// caller. The caller must never be inferred from the object itself.
func requesterIdentity(ctx context.Context) (authz.Identity, error) {
	request, err := admission.RequestFromContext(ctx)
	if err != nil {
		return authz.Identity{}, fmt.Errorf("cannot determine requester identity: %w", err)
	}
	return authz.Identity{
		Username: request.UserInfo.Username,
		Groups:   request.UserInfo.Groups,
	}, nil
}

// +kubebuilder:webhook:path=/mutate-user-sealos-io-v1-operationrequest,mutating=true,failurePolicy=fail,sideEffects=None,groups=user.sealos.io,resources=operationrequests,verbs=create;update,versions=v1,name=moperationrequest.kb.io,admissionReviewVersions=v1
//+kubebuilder:object:generate=false

type ReqMutator struct {
	client.Client
}

func (r ReqMutator) Default(ctx context.Context, obj runtime.Object) error {
	req, ok := obj.(*Operationrequest)
	if !ok {
		return errors.New("obj convert Operationrequest is error")
	}
	// mutate the request with an owner label
	operationrequestlog.Info("mutate", "name", req.Name)
	req.ObjectMeta = initAnnotationAndLabels(req.ObjectMeta)
	req.Labels[UserLabelOwnerKey] = req.Spec.User

	request, err := admission.RequestFromContext(ctx)
	if err != nil {
		return fmt.Errorf("cannot determine requester identity: %w", err)
	}
	// Always record the real creator on create; an annotation supplied by the
	// client must never be trusted.
	if request.Operation == admissionv1.Create || req.Annotations[UserAnnotationCreatorKey] == "" {
		req.Annotations[UserAnnotationCreatorKey] = request.UserInfo.Username
	}
	return nil
}

//+kubebuilder:webhook:path=/validate-user-sealos-io-v1-operationrequest,mutating=false,failurePolicy=fail,sideEffects=None,groups=user.sealos.io,resources=operationrequests,verbs=create;update,versions=v1,name=voperationrequest.kb.io,admissionReviewVersions=v1
//+kubebuilder:object:generate=false

type ReqValidator struct {
	client.Client
	Authorizer authz.Authorizer
}

func (r ReqValidator) authorizer() authz.Authorizer {
	if r.Authorizer != nil {
		return r.Authorizer
	}
	return authz.NewClientAuthorizer(r.Client)
}

func (r ReqValidator) ValidateCreate(
	ctx context.Context,
	obj runtime.Object,
) (admission.Warnings, error) {
	req, ok := obj.(*Operationrequest)
	if !ok {
		message := "obj convert Operationrequest is error"
		return admission.Warnings{message}, errors.New(message)
	}

	identity, err := requesterIdentity(ctx)
	if err != nil {
		return admission.Warnings{err.Error()}, err
	}
	allowed, reason, err := authz.OperationRequestDecision(
		ctx,
		r.authorizer(),
		identity,
		req.Spec.User,
		req.Spec.Namespace,
	)
	if err != nil {
		message := fmt.Sprintf("authorize operation request: %v", err)
		return admission.Warnings{message}, errors.New(message)
	}
	if !allowed {
		message := "operation request denied: " + reason
		return admission.Warnings{message}, errors.New(message)
	}

	// list all requests in the same namespace with a same owner
	var reqList OperationrequestList
	err = r.List(
		ctx,
		&reqList,
		client.InNamespace(req.Namespace),
		client.MatchingLabels{UserLabelOwnerKey: req.Spec.User},
	)
	if client.IgnoreNotFound(err) != nil {
		operationrequestlog.Error(err, "list operationrequest error")
		return admission.Warnings{"list operationrequest error"}, err
	}

	for _, item := range reqList.Items {
		if item.Status.Phase != RequestCompleted {
			operationrequestlog.Info(
				"there is a request not completed, can not create new request",
				"name",
				item.Name,
				"phase",
				item.Status.Phase,
			)
			message := "there is a request not completed, can not create new request"
			return admission.Warnings{message}, errors.New(message)
		}
	}
	return admission.Warnings{}, nil
}

func (r ReqValidator) ValidateUpdate(
	ctx context.Context,
	oldObj, newObj runtime.Object,
) (admission.Warnings, error) {
	oldReq, ok := oldObj.(*Operationrequest)
	if !ok {
		message := "obj convert Operationrequest error"
		return admission.Warnings{message}, errors.New(message)
	}
	newReq, ok := newObj.(*Operationrequest)
	if !ok {
		message := "obj convert Operationrequest error"
		return admission.Warnings{message}, errors.New(message)
	}
	if oldReq.Spec != newReq.Spec {
		message := "operation request spec do not support update"
		return admission.Warnings{message}, errors.New(message)
	}
	if oldReq.Annotations[UserAnnotationCreatorKey] != newReq.Annotations[UserAnnotationCreatorKey] {
		message := "operation request creator do not support update"
		return admission.Warnings{message}, errors.New(message)
	}

	identity, err := requesterIdentity(ctx)
	if err != nil {
		return admission.Warnings{err.Error()}, err
	}
	if identity.Username != newReq.Annotations[UserAnnotationCreatorKey] {
		allowed, reason, err := authz.OperationRequestDecision(
			ctx,
			r.authorizer(),
			identity,
			newReq.Spec.User,
			newReq.Spec.Namespace,
		)
		if err != nil {
			message := fmt.Sprintf("authorize operation request: %v", err)
			return admission.Warnings{message}, errors.New(message)
		}
		if !allowed {
			message := "operation request update denied: " + reason
			return admission.Warnings{message}, errors.New(message)
		}
	}
	return admission.Warnings{}, nil
}

func (r ReqValidator) ValidateDelete(
	_ context.Context,
	_ runtime.Object,
) (admission.Warnings, error) {
	return admission.Warnings{}, nil
}
