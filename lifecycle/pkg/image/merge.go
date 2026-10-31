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

package image

// nosemgrep: go.lang.security.audit.xss.import-text-template.import-text-template
import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/labring/sealos/pkg/types/v1beta1"
	"github.com/labring/sealos/pkg/utils/maps"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

var (
	dockerfileLabelKeyRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
	dockerfileEnvKeyRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
)

// validateDockerfileValue rejects newlines, NUL and other control characters
// so image metadata cannot terminate the current Dockerfile instruction and
// inject a new one (for example RUN).
func validateDockerfileValue(field, value string) error {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("image %s %q contains a control character", field, value)
		}
	}
	return nil
}

// dockerfileQuote escapes a value and wraps it in double quotes so it stays a
// single Dockerfile token. backslashes and quotes are escaped before the
// dollar-sign handling to preserve the previous literal-$ behaviour.
func dockerfileQuote(value string, cmd bool) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + escapeDollarSign(value, cmd) + `"`
}

func escapeDollarSign(s string, cmd bool) string {
	if cmd {
		return strings.ReplaceAll(s, "$", "\\$")
	}
	var buffer bytes.Buffer
	for i := 0; i < len(s); i++ {
		if s[i] == '$' {
			if i+1 < len(s) && s[i+1] == '(' {
				buffer.WriteByte(s[i])
			} else {
				buffer.WriteString("\\$")
			}
		} else {
			buffer.WriteByte(s[i])
		}
	}
	return buffer.String()
}

func MergeDockerfileFromImages(imageObjList []map[string]v1.Image) (string, error) {
	var labels map[string]string
	var envs map[string]string
	var cmds []string
	var entrypoints []string
	var isRootfs bool
	imageNames := make([]string, 0)
	for _, oci := range imageObjList {
		for name, val := range oci {
			imageNames = append(imageNames, name)
			labels = maps.Merge(labels, val.Config.Labels)

			if val.Config.Labels != nil {
				if key := maps.GetFromKeys(
					val.Config.Labels,
					v1beta1.ImageTypeKeys...); key == string(
					v1beta1.RootfsImage,
				) {
					isRootfs = true
				}
			}
			envs = maps.Merge(envs, maps.FromSlice(val.Config.Env))
			cmds = append(cmds, val.Config.Cmd...)
			entrypoints = append(entrypoints, val.Config.Entrypoint...)
		}
	}
	delete(envs, "PATH")
	if isRootfs {
		maps.SetKeys(labels, v1beta1.ImageTypeKeys, string(v1beta1.RootfsImage))
	}
	for k, v := range envs {
		if !dockerfileEnvKeyRe.MatchString(k) {
			return "", fmt.Errorf("invalid env key %q in image metadata", k)
		}
		if err := validateDockerfileValue("env value", v); err != nil {
			return "", err
		}
	}
	for k, label := range labels {
		if !dockerfileLabelKeyRe.MatchString(k) {
			return "", fmt.Errorf("invalid label key %q in image metadata", k)
		}
		if err := validateDockerfileValue("label value", label); err != nil {
			return "", err
		}
		labels[k] = dockerfileQuote(label, false)
	}
	for i, entrypoint := range entrypoints {
		if err := validateDockerfileValue("entrypoint", entrypoint); err != nil {
			return "", err
		}
		entrypoints[i] = dockerfileQuote(entrypoint, true)
	}
	for i, cmd := range cmds {
		if err := validateDockerfileValue("cmd", cmd); err != nil {
			return "", err
		}
		cmds[i] = dockerfileQuote(cmd, true)
	}
	for _, name := range imageNames {
		if err := validateDockerfileValue("image name", name); err != nil {
			return "", err
		}
	}
	t := template.New("")
	t, err := t.Parse(
		`FROM scratch
MAINTAINER labring
{{- if .Labels }}
LABEL {{ .Labels }}
{{- end }}
{{- if .Envs }}
ENV {{ .Envs }}
{{- end }}
{{- if .Entrypoints }}
ENTRYPOINT [{{ .Entrypoints }}]
{{- end }}
{{- if .CMDs }}
CMD [{{ .CMDs }}]
{{- end }}
{{- if .Images }}
{{- range .Images }}
COPY --from={{.}}   . .
{{- end }}
{{- end }}`,
	)
	if err != nil {
		return "", err
	}
	data := map[string]any{
		"Labels":      maps.ToString(labels, " \\\n\t"),
		"Envs":        maps.ToString(envs, " \\\n\t"),
		"Entrypoints": strings.Join(entrypoints, ","),
		"CMDs":        strings.Join(cmds, ","),
		"Images":      imageNames,
	}

	out := bytes.NewBuffer(nil)
	err = t.Execute(out, data)
	if err != nil {
		return "", err
	}
	return out.String(), nil
}
