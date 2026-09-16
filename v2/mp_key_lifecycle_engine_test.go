package tdnsmp

import (
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
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
	zoneSignedBy(t, mpzd, "agent.us.example.", "p1", "p2", "p3")

	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "signer", Agents: []*PeerConf{{Identity: "agent.us.example."}}})
	conf.Config.Internal.KeyDB = kdb
	// with no identity of ours among the signers this provider is not a
	// signer of the zone: no other signers to wait for, and the engine
	// does not run the zone (it would wait on itself otherwise)
	if got, ok := otherSignerLabels(mpzd, &MultiProviderConf{}); ok || len(got) != 0 {
		t.Errorf("with no label of ours: %v ok=%v, want none and not a signer", got, ok)
	}
	if got, ok := otherSignerLabels(mpzd, conf.MpConfig()); !ok || len(got) != 3 {
		t.Errorf("as a signer: %v ok=%v, want p1 p2 p3", got, ok)
	}

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
	mpzd.DnssecPolicy.Clamping.Margin = 2 * time.Hour // the clamp is mechanism (Q1): not the withdrawal margin
	pol = policyFor(conf, mpzd.ZoneData)
	if pol.KSKLifetime != 30*24*time.Hour || pol.Margin != 45*time.Minute {
		t.Errorf("KSK lifetime %s margin %s, want 720h from the policy and 45m (the propagation delay, until the kasp has a retire safety)", pol.KSKLifetime, pol.Margin)
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
	if !e.Signal(mpzd.ZoneName, 4711, "propagated", "", time.Time{}) {
		t.Error("a signal for an owned zone was not claimed by the engine")
	}
	if e.Signal("other.example.", 4711, "propagated", "", time.Time{}) {
		t.Error("a signal for a zone not owned was claimed")
	}
}
