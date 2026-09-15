package tdnsmp

import (
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The signer's wire and policy: the other signers from the zone's
// HSYNCPARAM minus this provider's label, and the owner's policy from
// tdns's policy and kasp.
func TestSignerWireOtherSignersAndPolicy(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	mpzd := signerTestZone(t, "wire.owned.example.", kdb)
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	hp := &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{&core.HSYNCPARAMSigners{Signers: []string{"p1", "p2", "p3"}}}}
	prr := &dns.PrivateRR{Hdr: dns.RR_Header{Name: mpzd.ZoneName, Rrtype: core.TypeHSYNCPARAM, Class: dns.ClassINET, Ttl: 3600}, Data: hp}
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{prr}})
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	mpzd.InstallInitialSnapshot()

	// with no identity of ours matched, every signer is another signer
	got := otherSignerLabels(mpzd, &MultiProviderConf{})
	if len(got) != 3 {
		t.Errorf("other signers with no label of ours: %v, want p1 p2 p3", got)
	}

	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	conf.Config.Dnssec.Kasp.PropagationDelay = "45m"
	conf.Config.Dnssec.Kasp.StandbyKskCount = 2
	pol := policyFor(conf, mpzd.ZoneData)
	if pol.KSKAlgorithm != dns.ED25519 || pol.ZSKAlgorithm != dns.ED25519 {
		t.Errorf("algorithms %d/%d, want ED25519", pol.KSKAlgorithm, pol.ZSKAlgorithm)
	}
	if pol.PropagationDelay != 45*time.Minute {
		t.Errorf("propagation delay %s, want 45m from kasp", pol.PropagationDelay)
	}
	if pol.StandbyKSK != 2 || pol.StandbyZSK != 1 {
		t.Errorf("standby counts KSK %d ZSK %d, want 2 and 1", pol.StandbyKSK, pol.StandbyZSK)
	}
	if pol.KSKLifetime != 0 || pol.ZSKLifetime != 0 {
		t.Errorf("lifetimes %s/%s, want forever (0) when the policy sets none", pol.KSKLifetime, pol.ZSKLifetime)
	}
	if pol.ResendAfter != 10*time.Minute {
		t.Errorf("resend %s, want the 10m default", pol.ResendAfter)
	}
	mpzd.DnssecPolicy.KSK.Lifetime = 30 * 86400
	mpzd.DnssecPolicy.Clamping.Margin = 2 * time.Hour
	pol = policyFor(conf, mpzd.ZoneData)
	if pol.KSKLifetime != 30*24*time.Hour || pol.Margin != 2*time.Hour {
		t.Errorf("KSK lifetime %s margin %s, want 720h and 2h from the policy", pol.KSKLifetime, pol.Margin)
	}

	// the engine: a zone not taken has no driver; a taken one gets one
	owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return kdb })
	e := NewKeyLifecycleEngine(conf, owner)
	if e.driver(mpzd.ZoneName) != nil {
		t.Error("a driver for a zone the owner has not taken")
	}
	owner.Take(mpzd.ZoneName)
	if e.driver(mpzd.ZoneName) == nil {
		t.Error("no driver for a taken zone")
	}
	if !e.Signal(mpzd.ZoneName, 4711, "propagated", "") {
		t.Error("a signal for an owned zone was not claimed by the engine")
	}
	if e.Signal("other.example.", 4711, "propagated", "") {
		t.Error("a signal for a zone not owned was claimed")
	}
}
