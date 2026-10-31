// Copyright © 2023 sealos.
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

package ssh

import (
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/containers/storage/pkg/homedir"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/labring/sealos/pkg/utils/file"
	"github.com/labring/sealos/pkg/utils/logger"
)

type Option struct {
	stdout                bool
	sudo                  bool
	user                  string
	password              string
	privateKey            string
	rawPrivateKeyData     string
	passphrase            string
	timeout               time.Duration
	hostKeyCallback       ssh.HostKeyCallback
	insecureIgnoreHostKey bool
}

func (o *Option) BindFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&o.stdout, "stdout", o.stdout, "print logs to stdout")
	fs.BoolVar(&o.sudo, "sudo", o.sudo, "enable sudo, user provide must be a superuser or sudoer")
	fs.StringVarP(&o.user, "user", "u", o.user, "username to authenticate as")
	fs.StringVarP(&o.password, "password", "p", o.password, "use given password to authenticate with")
	fs.StringVarP(&o.privateKey, "private-key", "i", o.privateKey,
		"selects a file from which the identity (private key) for public key authentication is read")
	fs.StringVar(&o.passphrase, "passphrase", o.passphrase, "passphrase for decrypting a PEM encoded private key")
	fs.DurationVar(&o.timeout, "timeout", o.timeout, "ssh connection establish timeout")
	fs.BoolVar(&o.insecureIgnoreHostKey, "insecure-ignore-host-key", o.insecureIgnoreHostKey,
		"INSECURE: skip SSH host key verification (also SEALOS_SSH_INSECURE_IGNORE_HOST_KEY=true)")
}

const (
	defaultUsername = "root"
)

func NewOption() *Option {
	homedir := homedir.Get()
	getSSHFile := func(filenames ...string) string {
		for _, fn := range filenames {
			absPath := path.Join(homedir, ".ssh", fn)
			if file.IsExist(absPath) {
				return absPath
			}
		}
		return ""
	}
	opt := &Option{
		user:                  defaultUsername,
		privateKey:            getSSHFile("id_rsa", "id_dsa"),
		timeout:               10 * time.Second,
		insecureIgnoreHostKey: insecureHostKeyFromEnv(),
	}
	opt.hostKeyCallback = opt.hostKeyVerifier()
	return opt
}

// hostKeyVerifier builds the default host key callback: verify against
// known_hosts unless the user explicitly opted out.
func (o *Option) hostKeyVerifier() ssh.HostKeyCallback {
	knownHosts, knownHostsErr := newKnownHostsCallback()
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if o.insecureIgnoreHostKey {
			logger.Warn("SSH host key verification is disabled; the connection to %s is vulnerable to MITM", hostname)
			return nil
		}
		if knownHostsErr != nil {
			return fmt.Errorf("ssh host key verification failed for %s: %v (set SEALOS_SSH_INSECURE_IGNORE_HOST_KEY=true to disable, not recommended)", hostname, knownHostsErr)
		}
		return knownHosts(hostname, remote, key)
	}
}

func insecureHostKeyFromEnv() bool {
	v, err := strconv.ParseBool(strings.TrimSpace(os.Getenv("SEALOS_SSH_INSECURE_IGNORE_HOST_KEY")))
	return err == nil && v
}

func knownHostsFiles() []string {
	if v := strings.TrimSpace(os.Getenv("SEALOS_SSH_KNOWN_HOSTS")); v != "" {
		return filepath.SplitList(v)
	}
	return []string{filepath.Join(homedir.Get(), ".ssh", "known_hosts")}
}

func newKnownHostsCallback() (ssh.HostKeyCallback, error) {
	var files []string
	for _, f := range knownHostsFiles() {
		if f != "" && file.IsExist(f) {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no known_hosts file found among %s", strings.Join(knownHostsFiles(), string(os.PathListSeparator)))
	}
	return knownhosts.New(files...)
}

type OptionFunc func(*Option)

func WithSudoEnable(b bool) OptionFunc {
	return func(o *Option) {
		o.sudo = b
	}
}

func WithStdoutEnable(b bool) OptionFunc {
	return func(o *Option) {
		o.stdout = b
	}
}

func WithUsername(u string) OptionFunc {
	return func(o *Option) {
		o.user = u
	}
}

func WithPassword(p string) OptionFunc {
	return func(o *Option) {
		o.password = p
	}
}

func WithRawPrivateKeyDataAndPhrase(raw, passphrase string) OptionFunc {
	return func(o *Option) {
		o.rawPrivateKeyData = raw
		o.passphrase = passphrase
	}
}

func WithPrivateKeyAndPhrase(pk, passphrase string) OptionFunc {
	return func(o *Option) {
		o.privateKey = pk
		o.passphrase = passphrase
	}
}

func WithTimeout(timeout time.Duration) OptionFunc {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return func(o *Option) {
		o.timeout = timeout
	}
}

func WithHostKeyCallback(fn ssh.HostKeyCallback) OptionFunc {
	return func(o *Option) {
		o.hostKeyCallback = fn
	}
}
