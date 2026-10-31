// Copyright 2026 labring.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controllers

import (
	"context"
	"testing"
	"time"

	userv1 "github.com/labring/sealos/controllers/user/api/v1"
	"github.com/labring/sealos/controllers/user/controllers/helper/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func renewalTestUser(refreshAt *metav1.Time, observed int32) *userv1.User {
	return &userv1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "alice"},
		Spec:       userv1.UserSpec{CSRExpirationSeconds: observed},
		Status: userv1.UserStatus{
			ObservedCSRExpirationSeconds: observed,
			KubeConfigRefreshAt:          refreshAt,
		},
	}
}

func TestKubeConfigRenewalDue(t *testing.T) {
	t.Parallel()
	now := time.Now()
	fresh := metav1.NewTime(now.Add(time.Hour))
	past := metav1.NewTime(now.Add(-time.Second))
	// A 7 day token issued 2 days ago is renewed at half of its lifetime in
	// 1.5 days; issued 4 days ago it is already past the renewal point.
	halfLifeFuture := metav1.NewTime(now.Add(1500 * time.Minute))
	halfLifePast := metav1.NewTime(now.Add(-time.Hour))
	tests := []struct {
		name string
		user *userv1.User
		want bool
	}{
		{
			name: "nil user renews",
			user: nil,
			want: true,
		},
		{
			name: "missing refresh deadline renews",
			user: renewalTestUser(nil, 7_200),
			want: true,
		},
		{
			name: "fresh status does not renew",
			user: renewalTestUser(&fresh, 7_200),
			want: false,
		},
		{
			name: "reached deadline renews",
			user: renewalTestUser(&past, 7_200),
			want: true,
		},
		{
			name: "younger than half lifetime does not renew",
			user: renewalTestUser(&halfLifeFuture, userv1.DefaultCSRExpirationSeconds),
			want: false,
		},
		{
			name: "older than half lifetime renews",
			user: renewalTestUser(&halfLifePast, userv1.DefaultCSRExpirationSeconds),
			want: true,
		},
		{
			name: "legacy lifetime policy renews before its deadline",
			user: renewalTestUser(&fresh, 1_000_000_000),
			want: true,
		},
		{
			name: "legacy spec without observed status renews",
			user: &userv1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "alice"},
				Spec:       userv1.UserSpec{CSRExpirationSeconds: 1_000_000_000},
				Status:     userv1.UserStatus{KubeConfigRefreshAt: &fresh},
			},
			want: true,
		},
		{
			name: "maximum lifetime does not renew",
			user: renewalTestUser(&fresh, userv1.MaxCSRExpirationSeconds),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := kubeConfigRenewalDue(tt.user, now); got != tt.want {
				t.Fatalf("kubeConfigRenewalDue() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestKubeConfigRefreshRequiredRespectsRotateAt(t *testing.T) {
	t.Parallel()
	now := time.Now()
	fresh := metav1.NewTime(now.Add(time.Hour))
	past := metav1.NewTime(now.Add(-time.Hour))
	rotateAt := metav1.NewTime(now.Add(-time.Minute))
	later := metav1.NewTime(now.Add(time.Minute))
	tests := []struct {
		name   string
		user   *userv1.User
		rotate *metav1.Time
		want   bool
	}{
		{
			name: "fresh status without rotation does not refresh",
			user: renewalTestUser(&fresh, userv1.DefaultCSRExpirationSeconds),
			want: false,
		},
		{
			name:   "pending rotation request refreshes",
			user:   renewalTestUser(&fresh, userv1.DefaultCSRExpirationSeconds),
			rotate: &rotateAt,
			want:   true,
		},
		{
			name: "processed rotation does not refresh",
			user: func() *userv1.User {
				user := renewalTestUser(&fresh, userv1.DefaultCSRExpirationSeconds)
				user.Status.ObservedKubeConfigRotateAt = &rotateAt
				return user
			}(),
			rotate: &rotateAt,
			want:   false,
		},
		{
			name: "changed rotation request refreshes",
			user: func() *userv1.User {
				user := renewalTestUser(&fresh, userv1.DefaultCSRExpirationSeconds)
				user.Status.ObservedKubeConfigRotateAt = &rotateAt
				return user
			}(),
			rotate: &later,
			want:   true,
		},
		{
			name: "elapsed lifetime refreshes without rotation",
			user: renewalTestUser(&past, userv1.DefaultCSRExpirationSeconds),
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.user.Spec.KubeConfigRotateAt = tt.rotate
			if got := kubeConfigRefreshRequired(tt.user, now); got != tt.want {
				t.Fatalf("kubeConfigRefreshRequired() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestKubeConfigRefreshTimeUsesHalfLifetime(t *testing.T) {
	t.Parallel()
	issuedAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		lifetime time.Duration
		want     time.Duration
	}{
		{name: "two hours", lifetime: 2 * time.Hour, want: time.Hour},
		{name: "seven days", lifetime: 7 * 24 * time.Hour, want: 7 * 12 * time.Hour},
		{name: "ten minutes", lifetime: 10 * time.Minute, want: 5 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := kubeConfigRefreshTime(issuedAt, issuedAt.Add(tt.lifetime))
			if delta := got.Sub(issuedAt); delta != tt.want {
				t.Fatalf("refresh offset = %v, want %v", delta, tt.want)
			}
		})
	}
}

func TestKubeConfigCurrentRejectsLegacyLifetimePolicy(t *testing.T) {
	t.Parallel()
	scheme := reconcileTestScheme(t)
	refreshAt := metav1.NewTime(time.Now().Add(time.Hour))
	user := benchmarkProcessedUser("alice", refreshAt.Time)
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:            user.Name,
			Namespace:       config.GetUserSystemNamespace(),
			OwnerReferences: []metav1.OwnerReference{reconcileTestOwnerReference(user)},
		},
		Secrets: []corev1.ObjectReference{{Name: "token-alice"}},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "token-alice",
			Namespace: config.GetUserSystemNamespace(),
			UID:       types.UID("secret-alice"),
			Annotations: map[string]string{
				corev1.ServiceAccountNameKey: user.Name,
			},
			OwnerReferences: []metav1.OwnerReference{reconcileTestOwnerReference(user)},
		},
	}
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sa, secret).Build()
	reconciler := &UserReconciler{cache: cli}
	state := &userReconcileState{serviceAccount: sa}

	if !reconciler.kubeConfigCurrent(context.Background(), user, state) {
		t.Fatal("current policy user was unexpectedly scheduled for renewal")
	}

	user.Spec.CSRExpirationSeconds = 1_000_000_000
	user.Status.ObservedCSRExpirationSeconds = 1_000_000_000
	if reconciler.kubeConfigCurrent(context.Background(), user, state) {
		t.Fatal("legacy lifetime policy user was not scheduled for renewal")
	}
}
