//go:build windows

package splitdns

import (
	"fmt"
	"net/netip"
)

type Manager struct {
	logf     logf
	nrptDB   *nrptDatabase
	trackKey string
}

type Config struct {
	Nameservers  []netip.Addr
	MatchDomains []string
}

type Binding struct {
	m *Manager

	ID string
}

func NewManager(logf logf) *Manager {
	if logf == nil {
		logf = func(format string, v ...any) {}
	}

	if !SupportsSplitDNS() {
		panic("This system does not support Split DNS")
	}

	ret := &Manager{
		logf:   logf,
		nrptDB: newNRPTDatabase(logf),
	}

	return ret
}

func (m *Manager) SplitDNS(cfg *Config) (*Binding, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	if len(cfg.MatchDomains) == 0 {
		return nil, fmt.Errorf("MatchDomains are required")
	}

	servers := make([]string, 0, len(cfg.Nameservers))
	for _, ns := range cfg.Nameservers {
		servers = append(servers, ns.String())
	}
	rid, err := m.nrptDB.writeSplitDNSConfig(servers, cfg.MatchDomains)
	if err != nil {
		return nil, fmt.Errorf("Failed to set NRPT: %w", err)
	}

	return &Binding{m: m, ID: rid}, nil
}

func (m *Manager) Binding(id string) *Binding {
	return &Binding{m: m, ID: id}
}

func (b *Binding) Unset() error {
	if err := b.m.nrptDB.deleteRule(b.ID); err != nil {
		return err
	}

	return nil
}
