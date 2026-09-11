package tdnsmp

import "testing"

func TestDeclaredRoleLabels_sharedIdentity(t *testing.T) {
	info := MPZoneInfo{
		Servers:  []string{"cpt", "fox", "hare"},
		Signers:  []string{"cpt", "hare"},
		Auditors: []string{"skrubb"},
	}
	got := declaredRoleLabels(info)
	if len(got) != 4 {
		t.Fatalf("labels = %v, want cpt fox hare skrubb", got)
	}
}

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
