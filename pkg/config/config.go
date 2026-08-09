package config

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/anchore/stereoscope/pkg/image"
)

// maskedPassword is what a non-empty stored password is replaced with in
// GetPublic()/toPublic()-style output; Save() recognizes it (or the legacy
// 6-asterisk form some older UI builds sent) as "unchanged, keep existing".
const maskedPassword = "********"

type RegistryAuth struct {
	Authority string `json:"authority"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	Token     string `json:"token,omitempty"`
	Source    string `json:"source,omitempty"` // "ui" or "mounted-secret"
}

type Config struct {
	HTTPProxy             string         `json:"httpProxy"`
	HTTPSProxy            string         `json:"httpsProxy"`
	NoProxy               string         `json:"noProxy"`
	InsecureSkipTLSVerify bool           `json:"insecureSkipTlsVerify"`
	InsecureUseHTTP       bool           `json:"insecureUseHttp"`
	RegistryAuths         []RegistryAuth `json:"registryAuths"`
}

type Manager struct {
	mu      sync.RWMutex
	dataDir string
	cfgFile string
	config  Config
	mAuths  []RegistryAuth
}

func NewManager(dataDir string) (*Manager, error) {
	cfgFile := filepath.Join(dataDir, "config.json")
	m := &Manager{
		dataDir: dataDir,
		cfgFile: cfgFile,
		config: Config{
			// Seed proxy defaults from the environment on first run only;
			// loadConfig() below overwrites this wholesale once config.json
			// exists, same as the previous Node implementation.
			HTTPProxy:     firstNonEmpty(os.Getenv("HTTP_PROXY"), os.Getenv("http_proxy")),
			HTTPSProxy:    firstNonEmpty(os.Getenv("HTTPS_PROXY"), os.Getenv("https_proxy")),
			NoProxy:       firstNonEmpty(os.Getenv("NO_PROXY"), os.Getenv("no_proxy")),
			RegistryAuths: []RegistryAuth{},
		},
	}
	m.loadMountedAuths()
	m.loadConfig()
	m.applyProxyEnv()
	return m, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// applyProxyEnv exports the configured proxy as process env vars so the
// registry client's default HTTP transport (http.ProxyFromEnvironment)
// picks it up. The proxy is a single global setting (not per-scan), so
// this is safe to do process-wide without racing concurrent scans.
func (m *Manager) applyProxyEnv() {
	m.mu.RLock()
	cfg := m.config
	m.mu.RUnlock()

	setOrUnset := func(key, val string) {
		if val == "" {
			_ = os.Unsetenv(key)
			return
		}
		_ = os.Setenv(key, val)
	}
	setOrUnset("HTTP_PROXY", cfg.HTTPProxy)
	setOrUnset("http_proxy", cfg.HTTPProxy)
	setOrUnset("HTTPS_PROXY", cfg.HTTPSProxy)
	setOrUnset("https_proxy", cfg.HTTPSProxy)
	setOrUnset("NO_PROXY", cfg.NoProxy)
	setOrUnset("no_proxy", cfg.NoProxy)
}

func mountedPullSecretPath() string {
	if p := os.Getenv("PULL_SECRET_PATH"); p != "" {
		return p
	}
	return "/etc/hullcheck/pull-secret/.dockerconfigjson"
}

func (m *Manager) loadMountedAuths() {
	path := mountedPullSecretPath()
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("config: no mounted pull secret at %s (%v) - continuing without it", path, err)
		return
	}
	var doc struct {
		Auths map[string]struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Auth     string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		log.Printf("config: mounted pull secret at %s is not valid JSON: %v", path, err)
		return
	}
	for authority, info := range doc.Auths {
		username, password := info.Username, info.Password
		if (username == "" || password == "") && info.Auth != "" {
			if decoded, err := base64.StdEncoding.DecodeString(info.Auth); err == nil {
				if idx := strings.IndexByte(string(decoded), ':'); idx != -1 {
					username = string(decoded[:idx])
					password = string(decoded[idx+1:])
				}
			}
		}
		m.mAuths = append(m.mAuths, RegistryAuth{
			Authority: authority,
			Username:  username,
			Password:  password,
			Source:    "mounted-secret",
		})
	}
	log.Printf("config: loaded %d registry auth(s) from mounted pull secret %s", len(m.mAuths), path)
}

func (m *Manager) loadConfig() {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.cfgFile)
	if err != nil {
		return
	}
	var loaded Config
	if err := json.Unmarshal(data, &loaded); err == nil {
		m.config = loaded
	}
}

func (m *Manager) Save(cfg Config) error {
	m.mu.Lock()

	// Preserve existing passwords if masked "*******" is sent
	authsMap := make(map[string]string)
	for _, a := range m.config.RegistryAuths {
		authsMap[a.Authority] = a.Password
	}

	var cleanAuths []RegistryAuth
	for _, a := range cfg.RegistryAuths {
		if a.Source == "mounted-secret" {
			continue
		}
		pwd := a.Password
		if pwd == maskedPassword || pwd == "******" {
			pwd = authsMap[a.Authority]
		}
		a.Password = pwd
		a.Source = "ui"
		cleanAuths = append(cleanAuths, a)
	}

	cfg.RegistryAuths = cleanAuths
	m.config = cfg

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		m.mu.Unlock()
		return err
	}
	writeErr := os.WriteFile(m.cfgFile, data, 0600)
	m.mu.Unlock()

	m.applyProxyEnv()
	return writeErr
}

func (m *Manager) GetPublic() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()

	combined := make([]RegistryAuth, 0, len(m.config.RegistryAuths)+len(m.mAuths))
	for _, a := range m.config.RegistryAuths {
		masked := a
		if masked.Password != "" {
			masked.Password = maskedPassword
		}
		masked.Source = "ui"
		combined = append(combined, masked)
	}
	for _, a := range m.mAuths {
		masked := a
		masked.Password = maskedPassword
		combined = append(combined, masked)
	}

	return Config{
		HTTPProxy:             m.config.HTTPProxy,
		HTTPSProxy:            m.config.HTTPSProxy,
		NoProxy:               m.config.NoProxy,
		InsecureSkipTLSVerify: m.config.InsecureSkipTLSVerify,
		InsecureUseHTTP:       m.config.InsecureUseHTTP,
		RegistryAuths:         combined,
	}
}

// BuildRegistryOptions merges mounted-secret, UI-configured and an optional
// one-off per-scan auth (highest priority) into the registry credentials
// syft/grype use in-process to pull an image - no on-disk docker config or
// registry.yaml needed since there's no child process to hand them to.
func (m *Manager) BuildRegistryOptions(perScanAuth *RegistryAuth, insecureSkipTLS, insecureUseHTTP bool) image.RegistryOptions {
	m.mu.RLock()
	mounted := append([]RegistryAuth{}, m.mAuths...)
	uiAuths := append([]RegistryAuth{}, m.config.RegistryAuths...)
	m.mu.RUnlock()

	byAuthority := make(map[string]RegistryAuth)
	for _, a := range mounted {
		if a.Authority != "" {
			byAuthority[a.Authority] = a
		}
	}
	for _, a := range uiAuths {
		if a.Authority != "" {
			byAuthority[a.Authority] = a
		}
	}
	if perScanAuth != nil && perScanAuth.Authority != "" {
		byAuthority[perScanAuth.Authority] = *perScanAuth
	}

	creds := make([]image.RegistryCredentials, 0, len(byAuthority))
	for authority, a := range byAuthority {
		creds = append(creds, image.RegistryCredentials{
			Authority: authority,
			Username:  a.Username,
			Password:  a.Password,
			Token:     a.Token,
		})
	}

	return image.RegistryOptions{
		InsecureSkipTLSVerify: insecureSkipTLS,
		InsecureUseHTTP:       insecureUseHTTP,
		Credentials:           creds,
	}
}
