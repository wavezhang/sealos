/*
Copyright 2023.

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
	"net"
	"os"
	"strings"
	"time"

	"github.com/labring/sealos/webhook/admission/pkg/code"
	"github.com/miekg/dns"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// log is for logging in this package.
var ilog = logf.Log.WithName("ingress-validating-webhook")

//+kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete

//+kubebuilder:webhook:path=/mutate-networking-k8s-io-v1-ingress,mutating=true,failurePolicy=ignore,sideEffects=None,groups=networking.k8s.io,resources=ingresses,verbs=create;update,versions=v1,name=mingress.sealos.io,admissionReviewVersions=v1
//+kubebuilder:object:generate=false

type IngressMutator struct {
	client.Client
	CnameDomains       DomainList
	IngressAnnotations map[string]string
}

func (m *IngressMutator) SetupWithManager(mgr ctrl.Manager) error {
	m.Client = mgr.GetClient()
	return builder.WebhookManagedBy(mgr).
		For(&netv1.Ingress{}).
		WithDefaulter(m).
		Complete()
}

func (m *IngressMutator) Default(_ context.Context, obj runtime.Object) error {
	i, ok := obj.(*netv1.Ingress)
	if !ok {
		return errors.New("obj convert Ingress is error")
	}

	for _, domain := range m.CnameDomains {
		if isUserNamespace(i.Namespace) && hasSubDomain(i, domain) {
			ilog.Info(
				"mutating ingress in user ns",
				"ingress namespace",
				i.Namespace,
				"ingress name",
				i.Name,
			)
			m.mutateUserIngressAnnotations(i)
		}
	}
	return nil
}

func (m *IngressMutator) mutateUserIngressAnnotations(i *netv1.Ingress) {
	initAnnotationAndLabels(&i.ObjectMeta)
	for k, v := range m.IngressAnnotations {
		i.Annotations[k] = v
	}
}

//+kubebuilder:object:generate=false

type IngressValidator struct {
	client.Client
	CnameDomains      DomainList
	DenyDomains       DomainList
	CnameCheckEnabled bool
	cache             cache.Cache
	IcpValidator      *IcpValidator
}

const IngressHostIndex = "host"

func (v *IngressValidator) SetupWithManager(mgr ctrl.Manager) error {
	ilog.Info("starting webhook cache map")

	v.Client = mgr.GetClient()
	v.cache = mgr.GetCache()
	v.IcpValidator = NewIcpValidator(
		os.Getenv("ICP_ENABLED") == "true",
		os.Getenv("ICP_ENDPOINT"),
		os.Getenv("ICP_KEY"),
	)

	err := v.cache.IndexField(
		context.Background(),
		&netv1.Ingress{},
		IngressHostIndex,
		func(obj client.Object) []string {
			ingress := obj.(*netv1.Ingress) //nolint:errcheck // IndexField is registered for Ingress objects only
			hosts := make([]string, 0, len(ingress.Spec.Rules))
			for _, rule := range ingress.Spec.Rules {
				hosts = append(hosts, normalizeFQDN(rule.Host))
			}
			return hosts
		},
	)
	if err != nil {
		return err
	}

	return builder.WebhookManagedBy(mgr).
		For(&netv1.Ingress{}).
		WithValidator(v).
		Complete()
}

//+kubebuilder:webhook:path=/validate-networking-k8s-io-v1-ingress,mutating=false,failurePolicy=ignore,sideEffects=None,groups=networking.k8s.io,resources=ingresses,verbs=create;update;delete,versions=v1,name=vingress.sealos.io,admissionReviewVersions=v1

func (v *IngressValidator) ValidateCreate(
	ctx context.Context,
	obj runtime.Object,
) (admission.Warnings, error) {
	i, ok := obj.(*netv1.Ingress)
	if !ok {
		return nil, errors.New("obj convert Ingress is error")
	}

	ilog.Info("validating create", "ingress namespace", i.Namespace, "ingress name", i.Name)
	err := v.validate(ctx, i)
	return nil, err
}

func (v *IngressValidator) ValidateUpdate(
	ctx context.Context,
	_, newObj runtime.Object,
) (admission.Warnings, error) {
	ni, ok := newObj.(*netv1.Ingress)
	if !ok {
		return nil, errors.New("obj convert Ingress is error")
	}
	// oi, ok := oldObj.(*netv1.Ingress)
	// if !ok {
	//	return errors.New("obj convert Ingress is error")
	//}
	ilog.Info("validating update", "ingress namespace", ni.Namespace, "ingress name", ni.Name)
	err := v.validate(ctx, ni)
	return nil, err
}

func (v *IngressValidator) ValidateDelete(
	_ context.Context,
	obj runtime.Object,
) (admission.Warnings, error) {
	i, ok := obj.(*netv1.Ingress)
	if !ok {
		return nil, errors.New("obj convert Ingress is error")
	}

	ilog.Info("validating delete", "ingress namespace", i.Namespace, "ingress name", i.Name)
	// delete ingress, pass validate
	return nil, nil
}

func (v *IngressValidator) validate(ctx context.Context, i *netv1.Ingress) error {
	// count validate cost time

	startTime := time.Now()
	defer func() {
		ilog.Info(
			"finished validate",
			"ingress namespace",
			i.Namespace,
			"ingress name",
			i.Name,
			"cost",
			time.Since(startTime),
		)
	}()

	request, _ := admission.RequestFromContext(ctx)
	ilog.Info(
		"validating",
		"ingress namespace",
		i.Namespace,
		"ingress name",
		i.Name,
		"user",
		request.UserInfo.Username,
		"userGroups",
		request.UserInfo.Groups,
	)
	if !isUserServiceAccount(request.UserInfo.Username) {
		ilog.Info("user is not user's serviceaccount, skip validate")
		return nil
	}

	if !isUserNamespace(i.Namespace) {
		ilog.Info("namespace is system namespace, skip validate")
		return nil
	}

	if err := v.checkHosts(i); err != nil {
		return err
	}

	checks := []func(context.Context, *netv1.Ingress, *netv1.IngressRule) error{v.checkDeny}
	if v.CnameCheckEnabled {
		checks = append(checks, v.checkCname)
	}
	checks = append(checks, v.checkOwner, v.checkIcp)

	for _, rule := range i.Spec.Rules {
		for _, check := range checks {
			if err := check(ctx, i, &rule); err != nil {
				return err
			}
		}
	}

	return nil
}

func normalizeFQDN(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	return strings.TrimSuffix(s, ".")
}

// validateNoWildcardHost rejects wildcard hosts: a tenant with
// "*.cloud.sealos.io" would otherwise hijack every unclaimed subdomain.
func validateNoWildcardHost(host string) error {
	if strings.Contains(host, "*") {
		return fmt.Errorf(
			code.MessageFormat,
			code.IngressFailedWildcardHostCheck,
			"wildcard ingress host "+host+" is not allowed",
		)
	}
	return nil
}

func (v *IngressValidator) checkHosts(i *netv1.Ingress) error {
	for _, rule := range i.Spec.Rules {
		if err := validateNoWildcardHost(rule.Host); err != nil {
			return err
		}
	}
	for _, tls := range i.Spec.TLS {
		for _, host := range tls.Hosts {
			if err := validateNoWildcardHost(host); err != nil {
				return err
			}
		}
	}
	return nil
}

// hostsOverlap reports whether two ingress hosts claim the same DNS names.
// Comparison is done on normalized names at label boundaries (dns.IsSubDomain)
// and treats a pre-existing wildcard entry as covering its subdomains.
func hostsOverlap(a, b string) bool {
	a, b = normalizeFQDN(a), normalizeFQDN(b)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	if parent, ok := strings.CutPrefix(a, "*."); ok {
		// A wildcard certificate/rule does not cover its own apex.
		return b != parent && dns.IsSubDomain(parent, b)
	}
	if parent, ok := strings.CutPrefix(b, "*."); ok {
		return a != parent && dns.IsSubDomain(parent, a)
	}
	return false
}

func (v *IngressValidator) checkDeny(
	_ context.Context,
	i *netv1.Ingress,
	rule *netv1.IngressRule,
) error {
	if len(v.DenyDomains) == 0 {
		return nil
	}
	host := normalizeFQDN(rule.Host)
	for _, domain := range v.DenyDomains {
		d := normalizeFQDN(domain)
		if d == "" {
			continue
		}
		if dns.IsSubDomain(d, host) {
			ilog.Info(
				"deny ingress host by forbidden domain suffix",
				"ingress namespace",
				i.Namespace,
				"ingress name",
				i.Name,
				"rule host",
				rule.Host,
				"forbidden domain",
				domain,
			)
			return fmt.Errorf(
				code.MessageFormat,
				code.IngressFailedDomainSuffixCheck,
				"ingress host "+rule.Host+" is under forbidden domain suffix "+domain,
			)
		}
	}
	return nil
}

func (v *IngressValidator) checkCname(
	ctx context.Context,
	i *netv1.Ingress,
	rule *netv1.IngressRule,
) error {
	ilog.Info(
		"checking cname",
		"ingress namespace",
		i.Namespace,
		"ingress name",
		i.Name,
		"rule host",
		rule.Host,
	)
	ilog.Info("domains:", "domains", strings.Join(v.CnameDomains, ","))
	// An empty domain list means the operator did not configure ownership
	// checks (for example a chart installed without the entrypoint). Skip
	// instead of rejecting every ingress.
	if len(v.CnameDomains) == 0 {
		ilog.Info("cnameDomains is empty, skip cname ownership check")
		return nil
	}
	host := normalizeFQDN(rule.Host)
	// Hosts inside the cluster's own domains need no DNS lookup: unmatched
	// hosts are subject to a live CNAME query, which may be unavailable in
	// air-gapped environments.
	for _, domain := range v.CnameDomains {
		d := normalizeFQDN(domain)
		if d == "" {
			continue
		}
		if dns.IsSubDomain(d, host) {
			ilog.Info(
				"ingress host is end with "+domain+", skip validate",
				"ingress namespace",
				i.Namespace,
				"ingress name",
				i.Name,
			)
			return nil
		}
	}
	// get cname and check if it is cname to domain
	cname, err := net.DefaultResolver.LookupCNAME(ctx, rule.Host)
	if err != nil {
		ilog.Error(err, "can not verify ingress host "+rule.Host+", lookup cname error")
		return err
	}
	// remove last dot and normalize case
	cname = normalizeFQDN(cname)
	for _, domain := range v.CnameDomains {
		d := normalizeFQDN(domain)
		if d == "" {
			continue
		}
		// if cname is not a subdomain of the allowed domain, return error
		if dns.IsSubDomain(d, cname) {
			ilog.Info(
				"ingress host "+rule.Host+" is cname to "+cname+", pass checkCname validate",
				"ingress namespace",
				i.Namespace,
				"ingress name",
				i.Name,
				"cname",
				cname,
			)
			return nil
		}
	}
	return fmt.Errorf(
		code.MessageFormat,
		code.IngressFailedCnameCheck,
		"can not verify ingress host "+rule.Host+", cname is not end with any domains in "+strings.Join(
			v.CnameDomains,
			",",
		),
	)
}

func (v *IngressValidator) checkOwner(
	ctx context.Context,
	i *netv1.Ingress,
	rule *netv1.IngressRule,
) error {
	host := normalizeFQDN(rule.Host)
	iList := &netv1.IngressList{}
	if err := v.cache.List(
		ctx,
		iList,
		client.MatchingFields{IngressHostIndex: host},
	); err != nil {
		ilog.Error(err, "can not verify ingress host "+rule.Host+", list ingress error")
		return fmt.Errorf(code.MessageFormat, code.IngressFailedOwnerCheck, err.Error())
	}

	for _, exitsIngress := range iList.Items {
		owned := false
		for _, existingRule := range exitsIngress.Spec.Rules {
			if hostsOverlap(existingRule.Host, rule.Host) {
				owned = true
				break
			}
		}
		if !owned {
			continue
		}
		if exitsIngress.Namespace != i.Namespace {
			ilog.Info(
				"ingress host "+rule.Host+" is owned by "+i.Namespace+", failed validate",
				"ingress namespace",
				i.Namespace,
				"ingress name",
				i.Name,
			)
			return fmt.Errorf(
				code.MessageFormat,
				code.IngressFailedOwnerCheck,
				"ingress host "+rule.Host+" is owned by other user, you can not create ingress with same host.",
			)
		}
	}
	// pass owner check
	ilog.Info(
		"ingress host "+rule.Host+" pass checkOwner validate",
		"ingress namespace",
		i.Namespace,
		"ingress name",
		i.Name,
	)
	return nil
}

func (v *IngressValidator) checkIcp(
	ctx context.Context,
	i *netv1.Ingress,
	rule *netv1.IngressRule,
) error {
	if !v.IcpValidator.enabled {
		ilog.Info(
			"icp is disabled, skip check icp",
			"ingress namespace",
			i.Namespace,
			"ingress name",
			i.Name,
			"rule host",
			rule.Host,
		)
		return nil
	}
	// check rule.host icp
	icpRep, err := v.IcpValidator.Query(ctx, rule)
	if err != nil {
		ilog.Error(err, "can not verify ingress host "+rule.Host+", icp query error")
		return fmt.Errorf(
			code.MessageFormat,
			code.IngressWebhookInternalError,
			"can not verify ingress host "+rule.Host+", icp query error",
		)
	}
	if icpRep.ErrorCode != 0 {
		ilog.Error(
			err,
			"icp query error",
			"ingress namespace",
			i.Namespace,
			"ingress name",
			i.Name,
			"rule host",
			rule.Host,
			"icp error code",
			icpRep.ErrorCode,
			"icp reason",
			icpRep.Reason,
		)
		return fmt.Errorf(code.MessageFormat, code.IngressWebhookInternalError, icpRep.Reason)
	}
	// if icpRep.Result.SiteLicense is empty, return error, failed validate
	if icpRep.Result.SiteLicense == "" {
		ilog.Info(
			"deny ingress host "+rule.Host+", icp query result is empty",
			"ingress namespace",
			i.Namespace,
			"ingress name",
			i.Name,
			"rule host",
			rule.Host,
			"icp result",
			icpRep.Result,
		)
		return fmt.Errorf(
			code.MessageFormat,
			code.IngressFailedIcpCheck,
			"icp query result is empty",
		)
	}
	// pass icp check
	ilog.Info(
		"ingress host "+rule.Host+" pass checkIcp validate",
		"ingress namespace",
		i.Namespace,
		"ingress name",
		i.Name,
		"rule host",
		rule.Host,
		"icp result",
		icpRep.Result,
	)
	return nil
}
