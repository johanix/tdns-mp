package tdnsmp

import "testing"

func TestDeclaredRoleLabels_onlyHSYNCPARAM(t *testing.T) {
	info := MPZoneInfo{
		Servers:  []string{"fox", "hare"},
		Signers:  []string{"fox", "hare"},
		Auditors: []string{"skrubb", "auden"},
	}
	got := declaredRoleLabels(info)
	want := map[string]bool{"auden": true, "fox": true, "hare": true, "skrubb": true}
	if len(got) != len(want) {
		t.Fatalf("labels = %v, want %v", got, want)
	}
	for _, lbl := range got {
		if !want[lbl] {
			t.Fatalf("unexpected label %q in %v", lbl, got)
		}
	}
}
