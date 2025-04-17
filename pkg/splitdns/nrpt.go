//go:build windows

package splitdns

import (
	"fmt"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	nrptBaseLocal = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`

	nrptOverrideDNS = 0x8 // bitmask value for "use the provided override DNS resolvers"

	// Apparently NRPT rules cannot handle > 50 domains.
	nrptMaxDomainsPerRule = 50

	// This is the name of the registry value the NRPT uses for storing a rule's version number.
	nrptRuleVersionName = `Version`

	// This is the name of the registry value the NRPT uses for storing a rule's list of domains.
	nrptRuleDomsName = `Name`

	// This is the name of the registry value the NRPT uses for storing a rule's list of DNS servers.
	nrptRuleServersName = `GenericDNSServers`

	// This is the name of the registry value the NRPT uses for storing a rule's flags.
	nrptRuleFlagsName = `ConfigOptions`
)

type nrptDatabase struct {
	mu   sync.Mutex
	logf logf
}

func newNRPTDatabase(logf logf) *nrptDatabase {
	if logf == nil {
		logf = func(format string, args ...any) {}
	}

	db := &nrptDatabase{
		logf: logf,
	}

	return db
}

func (db *nrptDatabase) writeSplitDNSConfig(servers []string, domains []string) (string, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if len(domains) > nrptMaxDomainsPerRule {
		return "", fmt.Errorf("too many domains: %d, max allowed: %d", len(domains), nrptMaxDomainsPerRule)
	}

	guid, err := windows.GenerateGUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate GUID: %w", err)
	}
	rid := guid.String()

	for i, domain := range domains {
		if !strings.HasPrefix(domain, ".") {
			domains[i] = "." + domain
		} else {
			domains[i] = domain
		}
	}

	if err := db.writeNRPTRule(rid, servers, domains); err != nil {
		return "", fmt.Errorf("failed to write NRPT rule: %w", err)
	}

	return rid, nil
}

func (db *nrptDatabase) deleteRule(ruleID string) error {
	roleKey := nrptBaseLocal + `\` + ruleID
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, roleKey); err != nil && err != registry.ErrNotExist {
		return fmt.Errorf("deleting NRPT rule key %q: %w", roleKey, err)
	}

	return nil
}

func (db *nrptDatabase) writeNRPTRule(ruleID string, servers, domains []string) error {
	roleKey := nrptBaseLocal + `\` + ruleID
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, roleKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("creating registry key %q: %w", roleKey, err)
	}
	defer key.Close()

	if err := writeNRPTValues(key, strings.Join(servers, ";"), domains); err != nil {
		return err
	}
	return nil
}

func writeNRPTValues(key registry.Key, servers string, doms []string) error {
	if err := key.SetDWordValue(nrptRuleVersionName, 1); err != nil {
		return err
	}

	if err := key.SetStringsValue(nrptRuleDomsName, doms); err != nil {
		return err
	}

	if err := key.SetStringValue(nrptRuleServersName, servers); err != nil {
		return err
	}

	return key.SetDWordValue(nrptRuleFlagsName, nrptOverrideDNS)
}
