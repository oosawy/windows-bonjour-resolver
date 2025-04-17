//go:build windows

package main

import (
	"flag"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/oosawy/windows-bonjour-resolver/pkg/splitdns"
)

var servers []string
var domains []string

func main() {
	flag.Func("servers", "DNS server list (comma-separated)", func(s string) error {
		servers = strings.Split(s, ",")
		return nil
	})
	flag.Func("domains", "Split DNS domain list (comma-separated)", func(s string) error {
		domains = strings.Split(s, ",")
		return nil
	})
	flag.Parse()

	var addrs []netip.Addr
	for _, server := range servers {
		addr, err := netip.ParseAddr(server)
		if err != nil {
			log.Fatalf("invalid server address: %s", server)
		}
		addrs = append(addrs, addr)
	}

	manager := splitdns.NewManager(log.Printf)

	cfg := &splitdns.Config{
		Nameservers:  addrs,
		MatchDomains: domains,
	}

	splited, err := manager.SplitDNS(cfg)
	if err != nil {
		log.Fatalf("failed to apply DNS settings: %v", err)
	}
	defer func() {
		err := splited.Unset()
		if err != nil {
			log.Fatalf("failed to revert DNS settings: %v", err)
		}
	}()

	log.Println("DNS settings have been applied")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
