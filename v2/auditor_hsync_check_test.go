package tdnsmp

import (
	"strings"
	"testing"
)

func containsSubstring(s, sub string) bool {
	return strings.Contains(s, sub)
}

func TestCheckHSYNCConfig_missingHSYNC3(t *testing.T) {
	info := MPZoneInfo{Servers: []string{"cpt", "fox"}}
	byLabel := map[string]string{"fox": "agent.fox.mp.axfr.net."}
	errs := checkHSYNCConfig(info, byLabel)
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want missing HSYNC3 for cpt", errs)
	}
}

func TestRefreshZoneHSYNCConfig_storesAndClears(t *testing.T) {
	sm := NewAuditStateManager()
	sm.RefreshZoneHSYNCConfig("z.")
	zs := sm.GetZone("z.")
	if zs == nil || len(zs.ConfigErrors) != 0 {
		t.Fatalf("expected no stored errors for unknown zone, got %v", zs)
	}

	errs := checkHSYNCConfig(
		MPZoneInfo{Servers: []string{"fox"}},
		map[string]string{"fox": "agent.fox.example."},
	)
	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	zs = sm.GetOrCreateZone("z.")
	zs.mu.Lock()
	zs.ConfigErrors = append([]string(nil), "stale")
	zs.mu.Unlock()

	sm.RefreshZoneHSYNCConfig("z.")
	got := sm.SnapshotZoneConfigErrors("z.")
	if len(got) != 0 {
		t.Fatalf("SnapshotZoneConfigErrors = %v, want cleared", got)
	}
}
