package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// tdns-mp #396, on the signer: a reload removes a provider's zone from the
// signer's config and a later one adds it back, with its DNSSEC policy. tdns
// builds a new ZoneData for it, and the signer's role turn acts on that one,
// without a restart: its start signs the live ZoneData, not the removed one
// whose stanza named no policy.

// addedBack is the zone as the reload that adds it back leaves it: a new
// ZoneData in tdns's zones, its config stub with the policy, not loaded yet.
// Unlike signerZoneUnpublished it leaves tdns-mp's wrapper cache alone, as a
// reload does.
func addedBack(t *testing.T, name string, kdb *tdns.KeyDB, records ...string) *tdns.ZoneData {
	t.Helper()
	text := fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 1 7200 1800 604800 7200\n"+
		"%s 3600 IN NS ns1.%s\nns1.%s 3600 IN A 192.0.2.1\n", name, name, name, name, name, name)
	for _, r := range records {
		text += name + " " + r + "\n"
	}
	zd := &tdns.ZoneData{
		ZoneName:  name,
		ZoneStore: tdns.MapZone,
		ZoneType:  tdns.Primary,
		Logger:    log.New(io.Discard, "", 0),
		Options:   map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
		KeyDB:     kdb,
		DnssecPolicy: &tdns.DnssecPolicy{
			Mode:         tdns.DnssecPolicyModeKSKZSK,
			KSKAlgorithm: dns.ED25519,
			ZSKAlgorithm: dns.ED25519,
			SigValidity:  tdns.PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
		},
	}
	if _, _, err := zd.ReadZoneData(text, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	tdns.Zones.Set(name, zd)
	return zd
}

// removeAndAddBack: the two reloads, and the re-added zone's first load
// through the wrapper a lookup gives, its MPdata as the set-up leaves it.
func (r *signerRig) removeAndAddBack(t *testing.T, records ...string) *tdns.ZoneData {
	t.Helper()
	zone := r.mpzd.ZoneName
	tdns.Zones.Remove(zone)
	live := addedBack(t, zone, r.kdb, records...)
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd.ZoneData != live {
		t.Errorf("the lookup after the re-add: found %v, the live ZoneData %v", ok, ok && mpzd.ZoneData == live)
	}
	mpzd.EnsureMP()
	if mpzd.MP.MPdata == nil {
		mpzd.MP.MPdata = &MPdata{Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}}
	}
	mpzd.MPPreRefresh(incomingCopy(t, zone, records...), nil, nil, r.conf.MpConfig())
	mpzd.InstallInitialSnapshot()
	r.mpzd = mpzd
	return live
}

// The RA1 path: the zone the signer started with named no policy and was
// withheld; it is removed and added back with its policy; handed its keys'
// step, its role turn signs the live ZoneData with tdns's real start.
func TestASignerZoneAddedBackStartsSigningItsLiveZoneData(t *testing.T) {
	const zone = "readded.adding.signer.example."
	other := testDnskey(t, zone, 257)
	records := append(sigRecords(`serial="5" servers="p2" signers="p2"`), "3600 IN DNSKEY 257 3 15 "+other.PublicKey)
	r := newSignerRig(t, zone, records...)
	var on []*tdns.ZoneData
	prev := startSigning
	startSigning = func(ctx context.Context, zd *tdns.ZoneData) error {
		on = append(on, zd)
		return zd.StartSigning(ctx, 0)
	}
	t.Cleanup(func() { startSigning = prev })
	r.notTaken(zone)

	// the zone as the signer started with it: no policy in its stanza, and
	// withheld by its first load
	r.firstLoad(t, records...)
	old := r.mpzd.ZoneData
	old.DnssecPolicy, old.DnssecPolicyName = nil, ""
	if !r.mpzd.Withheld() {
		t.Fatal("the zone the signer started with is not withheld")
	}

	live := r.removeAndAddBack(t, records...)
	if !r.mpzd.Withheld() {
		t.Fatal("the zone added back is not withheld by its first load")
	}
	r.hand(joinerHandover(t, zone, 6, true), sigUs)
	r.roleTurn()
	if len(on) != 1 || on[0] != live {
		t.Fatalf("StartSigning ran %d times, on the live ZoneData: %v; want once, on it", len(on), len(on) == 1 && on[0] == live)
	}
	if !live.Options[tdns.OptInlineSigning] || r.mpzd.Withheld() {
		t.Errorf("the zone added back: inline-signing %v, withheld %v; want it signing", live.Options[tdns.OptInlineSigning], r.mpzd.Withheld())
	}
	if old.Options[tdns.OptInlineSigning] {
		t.Error("the removed ZoneData was switched on")
	}
	soa, err := r.mpzd.GetRRset(zone, dns.TypeSOA)
	if err != nil || soa == nil || len(soa.RRSIGs) == 0 {
		t.Errorf("the zone added back serves an unsigned SOA: %+v (%v)", soa, err)
	}
}

// The agent's word that it has no copy was said of the removed ZoneData. The
// zone added back starts as at a start: it waits for its agent's word, and the
// next one acts on the live wrapper.
func TestTheAgentsNoCopyWordIsAskedAgainForAZoneAddedBack(t *testing.T) {
	const zone = "readded.nocopy.signer.example."
	records := sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)
	r := newSignerRig(t, zone, records...)
	var on []*tdns.ZoneData
	prev := startSigning
	startSigning = func(ctx context.Context, zd *tdns.ZoneData) error {
		on = append(on, zd)
		return prev(ctx, zd)
	}
	t.Cleanup(func() { startSigning = prev })
	noCopy := &ActingHandover{Zone: zone, Phase: PhaseSteady, NoCopy: true, Made: time.Now()}

	r.firstLoad(t, records...)
	r.hand(noCopy, sigUs)
	r.roleTurn()
	if len(on) != 1 || r.mpzd.Withheld() {
		t.Fatalf("its agent has no copy: started %d times, withheld %v; want it signing by its copy", len(on), r.mpzd.Withheld())
	}

	live := r.removeAndAddBack(t, records...)
	if !r.mpzd.Withheld() {
		t.Fatal("the zone added back is not withheld by its first load")
	}
	r.roleTurn()
	if len(on) != 1 {
		t.Errorf("the zone added back started on the removed one's word: %d starts", len(on))
	}
	r.hand(noCopy, sigUs)
	if d := r.mpzd.MP.MPdata; d == nil || !d.WeAreSigner {
		t.Errorf("the agent's next word did not reach the live wrapper: its data %+v", d)
	}
	r.roleTurn()
	if len(on) != 2 || on[1] != live || r.mpzd.Withheld() {
		t.Errorf("after the agent's word: %d starts, the last on the live ZoneData %v, withheld %v", len(on), len(on) == 2 && on[1] == live, r.mpzd.Withheld())
	}
}

// The reload's prune lets go of what the role book says of a ZoneData tdns no
// longer holds, and keeps what it says of the live one.
func TestTheRoleBookPruneKeepsOnlyLiveZoneData(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	gone := signerZoneWith(t, "gone.rolebook.signer.example.", kdb)
	kept := signerZoneWith(t, "kept.rolebook.signer.example.", kdb)
	replaced := signerZoneWith(t, "replaced.rolebook.signer.example.", kdb)
	conf := &Config{Config: &tdns.Config{}}
	b := &conf.InternalMp.signerRoles
	b.provisional = map[string]*tdns.ZoneData{}
	for _, mpzd := range []*MPZoneData{gone, kept, replaced} {
		b.provisional[canonicalName(mpzd.ZoneName)] = mpzd.ZoneData
		conf.roleFailure(mpzd, "a failure", errors.New("refused"))
	}
	tdns.Zones.Remove(gone.ZoneName)
	addedBack(t, replaced.ZoneName, kdb)

	b.prune()
	if !conf.agentHasNoCopy(kept) {
		t.Error("the live zone's no-copy word was dropped")
	}
	if _, ok := b.said[canonicalName(kept.ZoneName)]; !ok {
		t.Error("the live zone's failure was dropped")
	}
	for _, mpzd := range []*MPZoneData{gone, replaced} {
		key := canonicalName(mpzd.ZoneName)
		if _, ok := b.provisional[key]; ok {
			t.Errorf("%s: the no-copy word of a ZoneData tdns no longer holds is kept", mpzd.ZoneName)
		}
		if _, ok := b.said[key]; ok {
			t.Errorf("%s: the failure of a ZoneData tdns no longer holds is kept", mpzd.ZoneName)
		}
	}
}
