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
	"errors"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Credential lifetime policy. Issued kubeconfig credentials are short-lived by
// design. The requested lifetime is clamped when a credential is issued, not
// when the User object is written, so objects that still carry the legacy
// 1_000_000_000 second default keep validating while their credentials are
// re-issued with the current maximum.
const (
	// DefaultCSRExpirationSeconds is the lifetime used when the requested value
	// is absent or below MinCSRExpirationSeconds (7 days).
	DefaultCSRExpirationSeconds int32 = 7 * 24 * 60 * 60
	// MinCSRExpirationSeconds is the smallest accepted request (10 minutes).
	// Shorter values are treated as unset and use DefaultCSRExpirationSeconds.
	MinCSRExpirationSeconds int32 = 10 * 60
	// MaxCSRExpirationSeconds is the hard upper bound for issued credentials
	// (30 days). Longer requests are clamped to this value.
	MaxCSRExpirationSeconds int32 = 30 * 24 * 60 * 60
)

// NormalizeCSRExpirationSeconds returns the effective lifetime used when
// issuing credentials. The policy is:
//
//   - value < MinCSRExpirationSeconds: DefaultCSRExpirationSeconds
//   - MinCSRExpirationSeconds <= value <= MaxCSRExpirationSeconds: value
//   - value > MaxCSRExpirationSeconds: MaxCSRExpirationSeconds
//
// The requested value is preserved on the API object and only normalized at
// issuance time, so existing objects (for example ones defaulted to the legacy
// 1000000000 seconds) are re-issued with the maximum lifetime without a CRD
// migration.
func NormalizeCSRExpirationSeconds(value int32) int32 {
	switch {
	case value < MinCSRExpirationSeconds:
		return DefaultCSRExpirationSeconds
	case value > MaxCSRExpirationSeconds:
		return MaxCSRExpirationSeconds
	default:
		return value
	}
}

// UserSpec defines the desired state of User
type UserSpec struct {
	// expirationSeconds is the requested duration of validity of the issued
	// kubeconfig credential. The issuer may issue a credential with a different
	// validity duration so a client must check the issued credential to determine
	// the actual duration.
	//
	// The effective lifetime is clamped when the credential is issued: values
	// below 600 seconds (including 0) use the default of 604800 seconds (7 days),
	// and values above 2592000 seconds (30 days) are reduced to 2592000 seconds.
	// The controller renews the kubeconfig at half of the effective lifetime.
	//
	// +optional
	//+kubebuilder:default:=604800
	CSRExpirationSeconds int32 `json:"csrExpirationSeconds,omitempty"`
	// kubeConfigRotateAt 用于手动触发 kubeconfig 轮转。
	// 当字段被设置或更新时，controller 会重新请求 token 并重建 kubeconfig。
	// +optional
	KubeConfigRotateAt *metav1.Time `json:"kubeConfigRotateAt,omitempty"`
}
type RoleType string

const (
	OwnerRoleType     RoleType = "Owner"
	ManagerRoleType   RoleType = "Manager"
	DeveloperRoleType RoleType = "Developer"
)

type UserPhase string

// These are the valid phases of node.
const (
	UserPending UserPhase = "Pending"
	UserUnknown UserPhase = "Unknown"
	UserActive  UserPhase = "Active"
)

// UserStatus defines the observed state of User
type UserStatus struct {
	// Phase is the recently observed lifecycle phase of user
	//+kubebuilder:default:=Unknown
	Phase      UserPhase `json:"phase,omitempty"`
	KubeConfig string    `json:"kubeConfig"`
	//+kubebuilder:default:=604800
	ObservedCSRExpirationSeconds int32 `json:"observedCSRExpirationSeconds,omitempty"`
	// ObservedKubeConfigRotateAt 记录已处理的轮转请求时间戳。
	// +optional
	ObservedKubeConfigRotateAt *metav1.Time `json:"observedKubeConfigRotateAt,omitempty"`
	// KubeConfigRefreshAt is the next time the controller should refresh the
	// kubeconfig token: half of the lifetime of the currently issued credential.
	// It is persisted so a controller restart keeps the token refresh schedule
	// without retaining the kubeconfig payload in cache.
	// +optional
	KubeConfigRefreshAt *metav1.Time `json:"kubeConfigRefreshAt,omitempty"`
	// ObservedKubeConfigSecretUID identifies the Secret bound to the current
	// kubeconfig token and detects same-name Secret recreation.
	// +optional
	ObservedKubeConfigSecretUID string `json:"observedKubeConfigSecretUID,omitempty"`
	// The generation observed by the user controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Conditions contains the different condition statuses for this user.
	Conditions []Condition `json:"conditions,omitempty"`
}

type ConditionType string

const (
	Initialized ConditionType = "Initialized"
	Ready       ConditionType = "Ready"
)

type Condition struct {
	Type ConditionType `json:"type" protobuf:"bytes,1,opt,name=type,casttype=ConditionType"`
	// Status is the status of the condition. One of True, False, Unknown.
	Status v1.ConditionStatus `json:"status" protobuf:"bytes,2,opt,name=status,casttype=ConditionStatus"`
	// LastHeartbeatTime is the last time this condition was updated.
	// +optional
	LastHeartbeatTime metav1.Time `json:"lastHeartbeatTime,omitempty" protobuf:"bytes,3,opt,name=lastHeartbeatTime"`
	// LastTransitionTime is the last time the condition changed from one status to another.
	// +optional
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty" protobuf:"bytes,4,opt,name=lastTransitionTime"`
	// Reason is a (brief) reason for the condition's last status change.
	// +optional
	Reason string `json:"reason,omitempty" protobuf:"bytes,5,opt,name=reason"`
	// Message is a human-readable message indicating details about the last status change.
	// +optional
	Message string `json:"message,omitempty" protobuf:"bytes,6,opt,name=message"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="ExpirationSeconds",type="integer",JSONPath=".status.observedCSRExpirationSeconds"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// User is the Schema for the users API
type User struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   UserSpec   `json:"spec,omitempty"`
	Status UserStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// UserList contains a list of User
type UserList struct {
	metav1.TypeMeta `       json:",inline"`
	metav1.ListMeta `       json:"metadata,omitempty"`
	Items           []User `json:"items"`
}

func init() {
	SchemeBuilder.Register(&User{}, &UserList{})
}

func (r *User) validateCSRExpirationSeconds() error {
	if r.Spec.CSRExpirationSeconds == 0 {
		return errors.New("csrExpirationSeconds is not allowed to be 0")
	}
	return nil
}
