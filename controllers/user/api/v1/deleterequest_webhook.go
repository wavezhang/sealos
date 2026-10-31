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

var deleterequestlog = logf.Log.WithName("deleterequest-resource")

func (r *DeleteRequest) SetupWebhookWithManager(mgr ctrl.Manager) error {
	m := &DeleteRequestMutator{Client: mgr.GetClient()}
	v := &DeleteRequestValidator{
		Client:     mgr.GetClient(),
		Authorizer: authz.NewClientAuthorizer(mgr.GetClient()),
	}
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		WithDefaulter(m).
		WithValidator(v).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-user-sealos-io-v1-deleterequest,mutating=true,failurePolicy=fail,sideEffects=None,groups=user.sealos.io,resources=deleterequests,verbs=create;update,versions=v1,name=mdeleterequest.kb.io,admissionReviewVersions=v1
//+kubebuilder:object:generate=false

type DeleteRequestMutator struct {
	client.Client
}

func (r DeleteRequestMutator) Default(ctx context.Context, obj runtime.Object) error {
	req, ok := obj.(*DeleteRequest)
	if !ok {
		return errors.New("obj convert DeleteRequest is error")
	}
	deleterequestlog.Info("mutate", "name", req.Name)
	req.ObjectMeta = initAnnotationAndLabels(req.ObjectMeta)

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

//+kubebuilder:webhook:path=/validate-user-sealos-io-v1-deleterequest,mutating=false,failurePolicy=fail,sideEffects=None,groups=user.sealos.io,resources=deleterequests,verbs=create;update,versions=v1,name=vdeleterequest.kb.io,admissionReviewVersions=v1
//+kubebuilder:object:generate=false

type DeleteRequestValidator struct {
	client.Client
	Authorizer authz.Authorizer
}

func (r DeleteRequestValidator) authorizer() authz.Authorizer {
	if r.Authorizer != nil {
		return r.Authorizer
	}
	return authz.NewClientAuthorizer(r.Client)
}

func (r DeleteRequestValidator) ValidateCreate(
	ctx context.Context,
	obj runtime.Object,
) (admission.Warnings, error) {
	req, ok := obj.(*DeleteRequest)
	if !ok {
		message := "obj convert DeleteRequest is error"
		return admission.Warnings{message}, errors.New(message)
	}

	identity, err := requesterIdentity(ctx)
	if err != nil {
		return admission.Warnings{err.Error()}, err
	}
	allowed, reason, err := authz.DeleteRequestDecision(
		ctx,
		r.authorizer(),
		identity,
		req.Spec.User,
	)
	if err != nil {
		message := fmt.Sprintf("authorize delete request: %v", err)
		return admission.Warnings{message}, errors.New(message)
	}
	if !allowed {
		message := fmt.Sprintf("delete request denied: %s", reason)
		return admission.Warnings{message}, errors.New(message)
	}
	return admission.Warnings{}, nil
}

func (r DeleteRequestValidator) ValidateUpdate(
	ctx context.Context,
	oldObj, newObj runtime.Object,
) (admission.Warnings, error) {
	oldReq, ok := oldObj.(*DeleteRequest)
	if !ok {
		message := "obj convert DeleteRequest error"
		return admission.Warnings{message}, errors.New(message)
	}
	newReq, ok := newObj.(*DeleteRequest)
	if !ok {
		message := "obj convert DeleteRequest error"
		return admission.Warnings{message}, errors.New(message)
	}
	if oldReq.Spec != newReq.Spec {
		message := "delete request spec do not support update"
		return admission.Warnings{message}, errors.New(message)
	}
	if oldReq.Annotations[UserAnnotationCreatorKey] != newReq.Annotations[UserAnnotationCreatorKey] {
		message := "delete request creator do not support update"
		return admission.Warnings{message}, errors.New(message)
	}

	identity, err := requesterIdentity(ctx)
	if err != nil {
		return admission.Warnings{err.Error()}, err
	}
	if identity.Username != newReq.Annotations[UserAnnotationCreatorKey] {
		allowed, reason, err := authz.DeleteRequestDecision(
			ctx,
			r.authorizer(),
			identity,
			newReq.Spec.User,
		)
		if err != nil {
			message := fmt.Sprintf("authorize delete request: %v", err)
			return admission.Warnings{message}, errors.New(message)
		}
		if !allowed {
			message := fmt.Sprintf("delete request update denied: %s", reason)
			return admission.Warnings{message}, errors.New(message)
		}
	}
	return admission.Warnings{}, nil
}

func (r DeleteRequestValidator) ValidateDelete(
	_ context.Context,
	_ runtime.Object,
) (admission.Warnings, error) {
	return admission.Warnings{}, nil
}
