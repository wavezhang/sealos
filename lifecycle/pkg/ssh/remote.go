/*
Copyright 2022 cuisongliu@qq.com.

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

package ssh

// nosemgrep: go.lang.security.audit.xss.import-text-template.import-text-template
import (
	"fmt"
	"strconv"

	"github.com/labring/sealos/pkg/constants"
	"github.com/labring/sealos/pkg/template"
	"github.com/labring/sealos/pkg/utils/initsystem"
	"github.com/labring/sealos/pkg/utils/iputils"
	stringsutil "github.com/labring/sealos/pkg/utils/strings"
)

const (
	addHostsCommandFmt    = "hosts add --ip %s  --domain %s"
	deleteHostsCommandFmt = "hosts delete  --domain %s"
	hostnameCommandFmt    = "hostname"
	tokenCommandFmt       = "token %s %s"
	cGroupCommandFmt      = "cri cgroup-driver --short"
	socketCommandFmt      = "cri socket"
	initSystemCommandFmt  = "initsystem %s %s"
)

type RenderTemplate func(name, defaultStr string, data map[string]any) (string, error)

type Remote struct {
	pathResolver constants.PathResolver
	execer       Interface
}

func (s *Remote) HostsAdd(ip, host, domain string) error {
	cmd := fmt.Sprintf(
		addHostsCommandFmt,
		stringsutil.ShellQuote(host),
		stringsutil.ShellQuote(domain),
	)
	return s.executeRemoteUtilSubcommand(ip, cmd)
}

func (s *Remote) HostsDelete(ip, domain string) error {
	cmd := fmt.Sprintf(deleteHostsCommandFmt, stringsutil.ShellQuote(domain))
	return s.executeRemoteUtilSubcommand(ip, cmd)
}

func (s *Remote) Hostname(ip string) (string, error) {
	return s.outputRemoteUtilSubcommand(ip, hostnameCommandFmt)
}

func (s *Remote) IPVS(ip, vip string, masters []string) error {
	ipvsTemplate := `ipvs --vs {{.vip}}  {{range $h := .masters}}--rs  {{$h}} {{end}} --health-path /healthz --health-schem https --run-once`
	data := map[string]any{
		"vip":     stringsutil.ShellQuote(vip),
		"masters": quoteAll(masters),
	}
	out, err := template.RenderTemplate("ipvs", ipvsTemplate, data)
	if err != nil {
		return err
	}
	return s.executeRemoteUtilSubcommand(ip, out)
}

func (s *Remote) IPVSClean(ip, vip string) error {
	ipvsTemplate := `ipvs --vs {{.vip}}  -C`
	data := map[string]any{
		"vip": stringsutil.ShellQuote(vip),
		"ip":  iputils.GetHostIP(ip),
	}
	out, err := template.RenderTemplate("ipvs", ipvsTemplate, data)
	if err != nil {
		return err
	}
	return s.executeRemoteUtilSubcommand(ip, out)
}

func (s *Remote) StaticPod(
	ip, vip, name, image string,
	masters []string,
	path string,
	options ...string,
) error {
	staticPodIPVSTemplate := `static-pod lvscare --path {{.path}} --name {{.name}} --vip {{.vip}} --image {{.image}}  {{range $h := .masters}} --masters  {{$h}} {{end}} {{range $o := .options}} --options  {{$o}} {{end}}`
	data := map[string]any{
		"vip":     stringsutil.ShellQuote(vip),
		"image":   stringsutil.ShellQuote(image),
		"masters": quoteAll(masters),
		"name":    stringsutil.ShellQuote(name),
		"path":    stringsutil.ShellQuote(path),
		"options": quoteAll(options),
	}
	out, err := template.RenderTemplate("lvscare", staticPodIPVSTemplate, data)
	if err != nil {
		return err
	}

	return s.executeRemoteUtilSubcommand(ip, out)
}

func (s *Remote) Token(ip, config, certificateKey string) (string, error) {
	return s.outputRemoteUtilSubcommand(ip, fmt.Sprintf(tokenCommandFmt,
		stringsutil.ShellQuote(config), stringsutil.ShellQuote(certificateKey)))
}

func (s *Remote) CGroup(ip string) (string, error) {
	return s.outputRemoteUtilSubcommand(ip, cGroupCommandFmt)
}

func (s *Remote) Socket(ip string) (string, error) {
	return s.outputRemoteUtilSubcommand(ip, socketCommandFmt)
}

func (s *Remote) Cert(
	ip string,
	altNames []string,
	nodeIP, nodeName, serviceCIRD, dnsDomain string,
) error {
	certTemplate := `cert \
	{{if .nodeIP}} --node-ip {{.nodeIP}}{{end}}{{if .nodeName}} --node-name {{.nodeName}}{{end}} \
	{{if .serviceCIDR}} --service-cidr {{.serviceCIDR}}{{end}}{{if .dnsDomain}} --dns-domain {{.dnsDomain}}{{end}} \
	{{range $h := .altNames}} --alt-names {{$h}} {{end}}`
	data := map[string]any{
		"nodeIP":      stringsutil.ShellQuote(nodeIP),
		"nodeName":    stringsutil.ShellQuote(nodeName),
		"serviceCIDR": stringsutil.ShellQuote(serviceCIRD),
		"dnsDomain":   stringsutil.ShellQuote(dnsDomain),
		"altNames":    quoteAll(altNames),
	}
	out, err := template.RenderTemplate("cert", certTemplate, data)
	if err != nil {
		return err
	}
	return s.executeRemoteUtilSubcommand(ip, out)
}

type initSystem struct {
	target  string
	remoter *Remote
}

// quoteAll shell-quotes every element so template values can never break out
// of the generated command line.
func quoteAll(values []string) []string {
	quoted := make([]string, len(values))
	for i := range values {
		quoted[i] = stringsutil.ShellQuote(values[i])
	}
	return quoted
}

func (s *initSystem) ServiceEnable(service string) error {
	return s.remoter.executeRemoteUtilSubcommand(
		s.target,
		fmt.Sprintf(initSystemCommandFmt, "enable", stringsutil.ShellQuote(service)),
	)
}

func (s *initSystem) EnableCommand(_ string) string {
	return "not supported"
}

func (s *initSystem) ServiceStart(service string) error {
	return s.remoter.executeRemoteUtilSubcommand(
		s.target,
		fmt.Sprintf(initSystemCommandFmt, "start", stringsutil.ShellQuote(service)),
	)
}

func (s *initSystem) ServiceStop(service string) error {
	return s.remoter.executeRemoteUtilSubcommand(
		s.target,
		fmt.Sprintf(initSystemCommandFmt, "stop", stringsutil.ShellQuote(service)),
	)
}

func (s *initSystem) ServiceRestart(service string) error {
	return s.remoter.executeRemoteUtilSubcommand(
		s.target,
		fmt.Sprintf(initSystemCommandFmt, "restart", stringsutil.ShellQuote(service)),
	)
}

func (s *initSystem) ServiceExists(service string) bool {
	out, _ := s.remoter.outputRemoteUtilSubcommand(
		s.target,
		fmt.Sprintf(initSystemCommandFmt, "is-exists", stringsutil.ShellQuote(service)),
	)
	result, _ := strconv.ParseBool(out)
	return result
}

func (s *initSystem) ServiceIsEnabled(service string) bool {
	out, _ := s.remoter.outputRemoteUtilSubcommand(
		s.target,
		fmt.Sprintf(initSystemCommandFmt, "is-enabled", stringsutil.ShellQuote(service)),
	)
	result, _ := strconv.ParseBool(out)
	return result
}

func (s *initSystem) ServiceIsActive(service string) bool {
	out, _ := s.remoter.outputRemoteUtilSubcommand(
		s.target,
		fmt.Sprintf(initSystemCommandFmt, "is-active", stringsutil.ShellQuote(service)),
	)
	result, _ := strconv.ParseBool(out)
	return result
}

func (s *Remote) InitSystem(ip string) initsystem.InitSystem {
	return &initSystem{target: ip, remoter: s}
}

func NewRemoteFromSSH(clusterName string, sshInterface Interface) *Remote {
	return &Remote{
		execer:       sshInterface,
		pathResolver: constants.NewPathResolver(clusterName),
	}
}

func (s *Remote) executeRemoteUtilSubcommand(ip, cmd string) error {
	cmd = fmt.Sprintf("%s %s", s.pathResolver.RootFSSealctlPath(), cmd)
	if err := s.execer.CmdAsync(ip, cmd); err != nil {
		return fmt.Errorf("failed to execute remote command `%s`: %v", cmd, err)
	}
	return nil
}

func (s *Remote) outputRemoteUtilSubcommand(ip, cmd string) (string, error) {
	cmd = fmt.Sprintf("%s %s", s.pathResolver.RootFSSealctlPath(), cmd)
	return s.execer.CmdToString(ip, cmd, "")
}
