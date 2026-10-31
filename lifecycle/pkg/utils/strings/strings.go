/*
Copyright 2021 cuisongliu@qq.com.

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

package strings

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/labring/sealos/pkg/constants"
	"github.com/labring/sealos/pkg/template"
	"github.com/labring/sealos/pkg/utils/file"
	"github.com/labring/sealos/pkg/utils/logger"
	"golang.org/x/exp/slices"
)

func NotInIPList(slice []string, key string) bool {
	for _, s := range slice {
		if key == strings.Split(s, ":")[0] {
			return false
		}
	}
	return true
}

var emptyLineRe = regexp.MustCompile(`^\s*$`)

func IsEmptyLine(str string) bool {
	return emptyLineRe.MatchString(str)
}

func TrimWS(str string) string {
	return strings.Trim(str, "\n\t")
}

func TrimSpaceWS(str string) string {
	return strings.TrimRight(str, " \n\t")
}

func FilterNonEmptyFromSlice(list []string) (ret []string) {
	for i := range list {
		if strings.TrimSpace(list[i]) != "" {
			ret = append(ret, list[i])
		}
	}
	return ret
}

func FilterNonEmptyFromString(s, sep string) []string {
	data := strings.Split(s, sep)
	return FilterNonEmptyFromSlice(data)
}

// RemoveDuplicate removes duplicate entry in the list.
func RemoveDuplicate(list []string) []string {
	var result []string
	flagMap := map[string]struct{}{}
	for _, v := range list {
		if _, ok := flagMap[v]; !ok {
			flagMap[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}

// RemoveSubSlice remove dst element from src slice
func RemoveSubSlice(src, dst []string) []string {
	var ret []string
	for _, s := range src {
		if !slices.Contains(dst, s) {
			ret = append(ret, s)
		}
	}
	return ret
}

func RemoveFromSlice(ss []string, s string) (result []string) {
	for _, v := range ss {
		if v != s {
			result = append(result, v)
		}
	}
	return result
}

func Merge(ss []string, s string) []string {
	var ret []string
	for i := range ss {
		if ss[i] != s {
			ret = append(ret, ss[i])
		}
	}
	ret = append(ret, s)
	return ret
}

func FormatSize(size int64) (Size string) {
	if size < 1024 {
		Size = fmt.Sprintf("%.2fB", float64(size)/float64(1))
	} else if size < (1024 * 1024) {
		Size = fmt.Sprintf("%.2fKB", float64(size)/float64(1024))
	} else if size < (1024 * 1024 * 1024) {
		Size = fmt.Sprintf("%.2fMB", float64(size)/float64(1024*1024))
	} else {
		Size = fmt.Sprintf("%.2fGB", float64(size)/float64(1024*1024*1024))
	}
	return Size
}

func IsLetterOrNumber(k string) bool {
	for _, r := range k {
		if r == '_' {
			continue
		}
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) {
			return false
		}
	}
	return true
}

// shellEnvKeyRe restricts environment variable names to POSIX shell
// identifiers. Anything else could terminate the export statement.
var shellEnvKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ShellQuote returns s quoted for safe use as a single POSIX shell word.
// Embedded single quotes are escaped as '\” (close quote, escaped quote,
// reopen quote) so no character in s can leave the quoted context.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// RenderShellWithEnv prepends "export KEY=VALUE" statements to shell.
// Keys are validated as shell identifiers and values are single-quoted to
// prevent command injection from Clusterfile, image or host environment.
func RenderShellWithEnv(shell string, envs map[string]string) (string, error) {
	if len(envs) == 0 {
		return shell, nil
	}
	keys := make([]string, 0, len(envs))
	for k := range envs {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	var b strings.Builder
	for _, k := range keys {
		if !shellEnvKeyRe.MatchString(k) {
			return "", fmt.Errorf("invalid environment variable name %q", k)
		}
		v := envs[k]
		if strings.ContainsRune(v, 0) {
			return "", fmt.Errorf("environment variable %q contains NUL byte", k)
		}
		fmt.Fprintf(&b, "export %s=%s; ", k, ShellQuote(v))
	}
	b.WriteString(shell)
	return b.String(), nil
}

func RenderTextWithEnv(text string, envs map[string]string) string {
	replaces := make(map[string]string, 0)
	for k, v := range envs {
		replaces[fmt.Sprintf("$(%s)", k)] = v
		replaces[fmt.Sprintf("${%s}", k)] = v
		replaces[fmt.Sprintf("$%s", k)] = v
	}
	logger.Debug("renderTextFromEnv: replaces: %+v ; text: %s", replaces, text)
	for o, n := range replaces {
		text = strings.ReplaceAll(text, o, n)
	}
	return text
}

func RenderTemplatesWithEnv(filePaths string, envs map[string]string) error {
	var (
		renderEtc       = filepath.Join(filePaths, constants.EtcDirName)
		renderScripts   = filepath.Join(filePaths, constants.ScriptsDirName)
		renderManifests = filepath.Join(filePaths, constants.ManifestsDirName)
	)

	for _, dir := range []string{renderEtc, renderScripts, renderManifests} {
		logger.Debug("render env dir: %s", dir)
		if !file.IsExist(dir) {
			logger.Debug("Directory %s does not exist, skipping", dir)
			continue
		}

		if err := filepath.Walk(dir, func(path string, info os.FileInfo, errIn error) error {
			if errIn != nil {
				return errIn
			}
			if info.IsDir() || !strings.HasSuffix(info.Name(), constants.TemplateSuffix) {
				return nil
			}

			fileName := strings.TrimSuffix(path, constants.TemplateSuffix)
			if file.IsExist(fileName) {
				if err := os.Remove(fileName); err != nil {
					logger.Warn("failed to remove existing file [%s]: %v", fileName, err)
				}
			}

			writer, err := os.OpenFile(fileName, os.O_CREATE|os.O_RDWR, os.ModePerm)
			if err != nil {
				return fmt.Errorf("failed to open file [%s] for rendering: %v", path, err)
			}
			defer writer.Close()

			body, err := file.ReadAll(path)
			if err != nil {
				return err
			}

			t, isOk, err := template.TryParse(string(body))
			if isOk {
				if err != nil {
					return fmt.Errorf("failed to create template: %s %v", path, err)
				}
				if err := t.Execute(writer, envs); err != nil {
					return fmt.Errorf("failed to render env template: %s %v", path, err)
				}
			} else {
				return errors.New("parse template failed")
			}

			return nil
		}); err != nil {
			return fmt.Errorf("failed to render templates in directory %s: %v", dir, err)
		}
	}

	return nil
}

func TrimQuotes(s string) string {
	if len(s) >= 2 {
		if c := s[len(s)-1]; s[0] == c && (c == '"' || c == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
