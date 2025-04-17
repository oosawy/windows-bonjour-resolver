//go:build windows

package splitdns

import "golang.org/x/sys/windows/registry"

type logf func(format string, args ...any)

// SupportsSplitDNS checks if the system supports Split DNS (Windows 10 or later).
func SupportsSplitDNS() bool {
	const versionKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, versionKey, registry.READ)
	if err != nil {
		// Fail safe, assume old Windows.
		return false
	}
	defer key.Close()

	// This key above only exists in Windows 10 and above. Its mere
	// presence is good enough.
	if _, _, err := key.GetIntegerValue("CurrentMajorVersionNumber"); err != nil {
		return false
	}
	return true
}
