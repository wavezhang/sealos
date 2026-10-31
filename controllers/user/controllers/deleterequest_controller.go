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

package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	userv1 "github.com/labring/sealos/controllers/user/api/v1"
	"github.com/labring/sealos/controllers/user/controllers/helper"
	"github.com/labring/sealos/controllers/user/controllers/helper/authz"
	"github.com/labring/sealos/controllers/user/controllers/helper/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// DeleteRequestReconciler reconciles a DeleteRequest object
type DeleteRequestReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Logger   logr.Logger
	Recorder record.EventRecorder
	// Authorizer re-checks the creator recorded by the admission webhook before
	// deleting the user and its namespace.
	Authorizer authz.Authorizer

	// expirationTime is the time duration of the request is expired
	expirationTime time.Duration
	// retentionTime is the time duration of the request is retained after it is isCompleted
	retentionTime time.Duration
}

const DeleteRequestRequeueDuration time.Duration = 30 * time.Second

//+kubebuilder:rbac:groups=user.sealos.io,resources=deleterequests,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=user.sealos.io,resources=deleterequests/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=user.sealos.io,resources=deleterequests/finalizers,verbs=update

func (r *DeleteRequestReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	deleteRequest := &userv1.DeleteRequest{}
	if err := r.Get(ctx, req.NamespacedName, deleteRequest); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return r.reconcile(ctx, deleteRequest)
}

func (r *DeleteRequestReconciler) reconcile(
	ctx context.Context,
	request *userv1.DeleteRequest,
) (ctrl.Result, error) {
	r.Logger.V(1).
		Info("start reconcile deleterequest", "name", request.Name, "user", request.Spec.User)
	// count the time cost of handling the request
	startTime := time.Now()
	defer func() {
		r.Logger.V(1).Info("complete request handling", "handling cost time", time.Since(startTime))
	}()

	// delete OperationRequest first if its status is isCompleted and exist for retention time
	if r.isRetained(request) {
		r.Logger.Info("delete request", "name", request.Name)
		if err := r.deleteRequest(ctx, request); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	// return early if its status is isCompleted and didn't exist for retention time
	if r.isCompleted(request) {
		r.Logger.Info("request is completed and requeue", "name", request.Name)
		return ctrl.Result{RequeueAfter: DeleteRequestRequeueDuration}, nil
	}
	// change OperationRequest status to failed if it is expired
	if r.isExpired(request) {
		r.Logger.Info("request is expired, update status to failed", "name", request.Name)
		if err := r.updateRequestStatus(ctx, request, userv1.RequestFailed); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Re-validate the creator recorded by the admission webhook before any
	// destructive operation. The webhook is the primary gate; this check
	// protects requests created while the webhook was disabled or whose creator
	// lost the permission afterwards.
	allowed, reason, err := r.authorize(ctx, request)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !allowed {
		r.Logger.Info("delete request denied", "name", request.Name, "reason", reason)
		r.Recorder.Eventf(
			request,
			corev1.EventTypeWarning,
			"Unauthorized",
			"DeleteRequest denied: %s",
			reason,
		)
		if err := r.denyRequest(ctx, request, reason); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// handle the request

	// get user
	user := userv1.User{}
	if err := r.Get(ctx, client.ObjectKey{Name: request.Spec.User}, &user); err != nil {
		r.Logger.Error(err, "get user error", "name", request.Spec.User)
		r.Recorder.Eventf(
			request,
			corev1.EventTypeWarning,
			"GetUserError",
			"get user %s error: %s",
			request.Spec.User,
			err.Error(),
		)
		return ctrl.Result{}, err
	}

	// delete user if it is not labeled deleted
	if !isUserDeleted(user) && !isGroupUser(user) {
		r.Logger.Info("user is not deleted or not a group user", "name", user.Name)
		r.Recorder.Eventf(
			request,
			corev1.EventTypeWarning,
			"UserNotDeleted",
			"user %s is not deleted or not a group user",
			user.Name,
		)
		return ctrl.Result{RequeueAfter: DeleteRequestRequeueDuration}, nil
	}

	// get namespace before deleting the user and confirm that it really belongs
	// to the target user
	ns := corev1.Namespace{}
	if err := r.Get(
		ctx,
		client.ObjectKey{Name: config.GetUsersNamespace(user.Name)},
		&ns,
	); err != nil {
		r.Logger.Error(err, "get ns error", "name", config.GetUsersNamespace(user.Name))
		r.Recorder.Eventf(
			request,
			corev1.EventTypeWarning,
			"GetNamespaceError",
			"get namespace %s error: %s",
			config.GetUsersNamespace(user.Name),
			err.Error(),
		)
		return ctrl.Result{}, err
	}
	if creator := ns.Annotations[userv1.UserAnnotationCreatorKey]; creator != "" &&
		creator != user.Name {
		reason := fmt.Sprintf(
			"namespace %s belongs to user %s, not %s",
			ns.Name,
			creator,
			user.Name,
		)
		r.Logger.Info("delete request denied", "name", request.Name, "reason", reason)
		r.Recorder.Eventf(
			request,
			corev1.EventTypeWarning,
			"Unauthorized",
			"DeleteRequest denied: %s",
			reason,
		)
		if err := r.denyRequest(ctx, request, reason); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// delete user
	if err := r.Delete(ctx, &user); err != nil {
		r.Logger.Error(err, "delete user error", "name", user.Name)
		r.Recorder.Eventf(
			request,
			corev1.EventTypeWarning,
			"DeleteUserError",
			"delete user %s error: %s",
			user.Name,
			err.Error(),
		)
		return ctrl.Result{}, err
	}

	// delete namespace
	if err := r.Delete(ctx, &ns); err != nil {
		r.Logger.Error(err, "delete ns error", "name", ns.Name)
		r.Recorder.Eventf(
			request,
			corev1.EventTypeWarning,
			"DeleteNamespaceError",
			"delete namespace %s error: %s",
			ns.Name,
			err.Error(),
		)
		return ctrl.Result{}, err
	}

	// update Request status to completed
	if err := r.updateRequestStatus(ctx, request, userv1.RequestCompleted); err != nil {
		r.Logger.Error(err, "update request status error", "name", request.Name)
		r.Recorder.Eventf(
			request,
			corev1.EventTypeWarning,
			"UpdateRequestStatusError",
			"update request %s status error: %s",
			request.Name,
			err.Error(),
		)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// isRetained returns true if the request is isCompleted and exist for retention time
func (r *DeleteRequestReconciler) isRetained(request *userv1.DeleteRequest) bool {
	if request.Status.Phase == userv1.RequestCompleted &&
		request.CreationTimestamp.Add(r.retentionTime).Before(time.Now()) {
		return true
	}
	return false
}

// isCompleted returns true if the request is isCompleted
func (r *DeleteRequestReconciler) isCompleted(request *userv1.DeleteRequest) bool {
	return request.Status.Phase == userv1.RequestCompleted
}

// isExpired returns true if the request is expired
func (r *DeleteRequestReconciler) isExpired(request *userv1.DeleteRequest) bool {
	if request.Status.Phase != userv1.RequestCompleted &&
		request.CreationTimestamp.Add(r.expirationTime).Before(time.Now()) {
		return true
	}
	return false
}

// SetupWithManager sets up the controller with the Manager.
func (r *DeleteRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	const controllerName = "deleterequest_controller"
	if r.Client == nil {
		r.Client = mgr.GetClient()
	}
	r.Logger = ctrl.Log.WithName(controllerName)
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor(controllerName)
	}
	r.Scheme = mgr.GetScheme()
	if r.Authorizer == nil {
		r.Authorizer = authz.NewClientAuthorizer(mgr.GetClient())
	}
	r.Logger.V(1).Info("init reconcile deleterequest controller")
	r.expirationTime = time.Minute * 10
	r.retentionTime = time.Minute * 30
	return ctrl.NewControllerManagedBy(mgr).
		For(&userv1.DeleteRequest{}, builder.OnlyMetadata).
		Complete(r)
}

func (r *DeleteRequestReconciler) deleteRequest(
	ctx context.Context,
	request *userv1.DeleteRequest,
) error {
	r.Logger.V(1).Info("deleting OperationRequest", "request", request)
	if err := r.Delete(ctx, request); client.IgnoreNotFound(err) != nil {
		r.Recorder.Eventf(
			request,
			corev1.EventTypeWarning,
			"Failed to delete OperationRequest",
			"Failed to delete OperationRequest %s/%s",
			request.Namespace,
			request.Name,
		)
		r.Logger.Error(err, "Failed to delete OperationRequest", "request", request)
		return fmt.Errorf("failed to delete OperationRequest %s: %w", request.Name, err)
	}
	r.Logger.V(1).Info("delete OperationRequest success")
	return nil
}

func (r *DeleteRequestReconciler) updateRequestStatus(
	ctx context.Context,
	request *userv1.DeleteRequest,
	phase userv1.RequestPhase,
) error {
	request.Status.Phase = phase
	if err := r.Status().Update(ctx, request); err != nil {
		r.Recorder.Eventf(
			request,
			corev1.EventTypeWarning,
			"Failed to update OperationRequest status",
			"Failed to update OperationRequest status %s/%s",
			request.Namespace,
			request.Name,
		)
		r.Logger.V(1).Info("update OperationRequest status failed", "request", request)
		return err
	}
	r.Logger.V(1).Info("update OperationRequest status success", "request", request)
	return nil
}

func (r *DeleteRequestReconciler) authorizer() authz.Authorizer {
	if r.Authorizer != nil {
		return r.Authorizer
	}
	return authz.NewClientAuthorizer(r.Client)
}

func (r *DeleteRequestReconciler) authorize(
	ctx context.Context,
	request *userv1.DeleteRequest,
) (bool, string, error) {
	creator := request.Annotations[userv1.UserAnnotationCreatorKey]
	if creator == "" {
		return false, "delete request does not record an authenticated creator", nil
	}
	return authz.DeleteRequestDecision(
		ctx,
		r.authorizer(),
		authz.Identity{Username: creator},
		request.Spec.User,
	)
}

// denyRequest marks a request as failed and records an explicit condition so
// that the rejection is visible on the object.
func (r *DeleteRequestReconciler) denyRequest(
	ctx context.Context,
	request *userv1.DeleteRequest,
	message string,
) error {
	now := metav1.Now()
	request.Status.Conditions = helper.UpdateCondition(request.Status.Conditions, userv1.Condition{
		Type:               userv1.Authorized,
		Status:             corev1.ConditionFalse,
		LastHeartbeatTime:  now,
		LastTransitionTime: now,
		Reason:             "Unauthorized",
		Message:            message,
	})
	return r.updateRequestStatus(ctx, request, userv1.RequestFailed)
}

// isUserDeleted returns true if the user is deleted
func isUserDeleted(user userv1.User) bool {
	return user.Labels["user.sealos.io/status"] == "Deleted"
}

// isGroupUser returns true if the user is a group user
func isGroupUser(user userv1.User) bool {
	return user.Labels["user.sealos.io/type"] == "Group"
}
