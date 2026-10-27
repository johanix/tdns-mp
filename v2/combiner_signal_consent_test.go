package tdnsmp

import (
	"errors"
	"fmt"
	"io"
	"log"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// tdns-mp #115: a stored publish instruction that says at-ns is acted on
// only while the customer's HSYNCPARAM says pubkey. Without the flag the
// combiner retracts the signal names it had published and keeps the
// instruction as apex-only: on an NS change, when it starts, and on a
// re-apply. The tests run the combiner's own functions against a database of
// their own: the agent's updates through CombinerProcessUpdate, a start
// through RegisterCombinerOnFirstLoad and the first-load callbacks it attaches.

const (
	consentProviderZone = "alpha.example."
	consentAgent        = "agent.alpha.example."
	consentNS1          = "ns1.alpha.example."
	consentNS2          = "ns2.alpha.example."
	consentNS3          = "ns3.alpha.example."
)

// consentCombiner is one provider's combiner: the provider zone alpha.example.,
// where the signal names live, and the customer zones a test adds. The
// database outlives a restart; the zones and what they hold in memory do not.
type consentCombiner struct {
	t     *testing.T
	kdb   *tdns.KeyDB
	hdb   *HsyncDB
	mp    *MultiProviderConf
	names map[string]bool
	dist  int
}

func newConsentCombiner(t *testing.T) *consentCombiner {
	t.Helper()
	kdb := newMPTestKeyDB(t)
	hdb := NewHsyncDB(kdb)
	if err := hdb.InitCombinerEditTables(); err != nil {
		t.Fatalf("InitCombinerEditTables: %v", err)
	}
	RegisterProviderZoneRRtypes(ProviderZoneConf{Zone: consentProviderZone, AllowedRRtypes: []string{"KEY"}})
	c := &consentCombiner{t: t, kdb: kdb, hdb: hdb, names: map[string]bool{},
		mp: &MultiProviderConf{Role: "combiner", Identity: "combiner.alpha.example.", Agents: []*PeerConf{{Identity: consentAgent}}}}
	t.Cleanup(func() {
		delete(providerZoneRRtypes, consentProviderZone)
		for name := range c.names {
			c.drop(name)
		}
	})
	return c
}

func (c *consentCombiner) drop(name string) {
	if zd, ok := tdns.Zones.Get(name); ok {
		zd.StopPublisher()
	}
	tdns.Zones.Remove(name)
	Zones.Invalidate(name)
}

// start is a combiner start: the zones are configured and none has loaded,
// nothing is in memory, and RegisterCombinerOnFirstLoad attaches the
// first-load callbacks. A second call is a restart.
func (c *consentCombiner) start(zones ...string) {
	c.t.Helper()
	pendingSignalKeys.mu.Lock()
	pendingSignalKeys.built = false
	pendingSignalKeys.entries = nil
	pendingSignalKeys.mu.Unlock()
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = c.kdb
	for _, name := range zones {
		c.drop(name)
		c.names[name] = true
		tdns.Zones.Set(name, &tdns.ZoneData{
			ZoneName:  name,
			ZoneStore: tdns.MapZone,
			ZoneType:  tdns.Primary,
			Logger:    log.New(io.Discard, "", 0),
			Options:   map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
			KeyDB:     c.kdb,
		})
		conf.InternalMp.MPZoneNames = append(conf.InternalMp.MPZoneNames, name)
	}
	conf.RegisterCombinerOnFirstLoad()
}

// load is a zone's first load, in tdns's order: the content is read, the
// combiner's pre-refresh takes the upstream apex and works out its role, the
// first snapshot is published, and the first-load callbacks run.
func (c *consentCombiner) load(name, text string) *MPZoneData {
	c.t.Helper()
	zd, ok := tdns.Zones.Get(name)
	if !ok {
		c.t.Fatalf("zone %s is not configured", name)
	}
	if _, _, err := zd.ReadZoneData(text, true); err != nil {
		c.t.Fatalf("ReadZoneData(%s): %v", name, err)
	}
	mpzd, ok := Zones.Get(name)
	if !ok {
		c.t.Fatalf("no MPZoneData for %s", name)
	}
	mpzd.snapshotUpstreamData(zd)
	mpzd.populateMPdata(c.mp, mpzd.signingSet())
	zd.InstallInitialSnapshot()
	callbacks := zd.OnFirstLoad
	zd.OnFirstLoad = nil
	for _, cb := range callbacks {
		cb(zd)
	}
	return mpzd
}

// consentProviderText is the provider zone as its file has it; with extra,
// the records a file written by an earlier run carries as well.
func consentProviderText(extra ...string) string {
	z := consentProviderZone
	text := fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 1 7200 1800 604800 7200\n%s 3600 IN NS %s\n", z, z, z, z, consentNS1)
	for _, rr := range extra {
		text += rr + "\n"
	}
	return text
}

func consentParams(pubkey bool) string {
	params := `servers="alpha" nsmgmt="agent" parentsync="agent"`
	if pubkey {
		params += " pubkey"
	}
	return params
}

// consentCustomerText is a customer zone as its owner publishes it: one of
// this provider's nameservers in the owner's own NS RRset, this provider's
// agent in HSYNC3, and HSYNCPARAM with or without the pubkey flag.
func consentCustomerText(zone string, pubkey bool) string {
	return fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 1 7200 1800 604800 7200\n"+
		"%s 3600 IN NS %s\n%s 3600 IN HSYNC3 ON alpha %s .\n%s 3600 IN HSYNCPARAM %s\n",
		zone, zone, zone, zone, consentNS1, zone, consentAgent, zone, consentParams(pubkey))
}

// ownerSays is the owner's edit of HSYNCPARAM, published as a refresh of the
// customer zone publishes it.
func (c *consentCombiner) ownerSays(mpzd *MPZoneData, pubkey bool) {
	c.t.Helper()
	rr, err := dns.NewRR(fmt.Sprintf("%s 3600 IN HSYNCPARAM %s", mpzd.ZoneName, consentParams(pubkey)))
	if err != nil {
		c.t.Fatalf("HSYNCPARAM: %v", err)
	}
	if _, err := mpzd.ZoneData.StageBatch(func(s tdns.Stager) (bool, error) {
		s.SetRRset(mpzd.ZoneName, core.RRset{Name: mpzd.ZoneName, RRtype: core.TypeHSYNCPARAM, Class: dns.ClassINET, RRs: []dns.RR{rr}})
		return true, nil
	}); err != nil {
		c.t.Fatalf("publishing the owner's HSYNCPARAM: %v", err)
	}
	if hp := mpzd.getHSYNCPARAM(); hp == nil || hp.HasPubkey() != pubkey {
		c.t.Fatalf("zone %s: HSYNCPARAM after the owner's edit is %v, want pubkey=%v", mpzd.ZoneName, hp, pubkey)
	}
}

func consentKey(zone string) string {
	return fmt.Sprintf("%s 3600 IN KEY 512 3 15 %s", zone, testZSKPub)
}

// update is one update from the agent, through the combiner's entry point.
func (c *consentCombiner) update(zone string, ops []core.RROperation, publish *core.PublishInstruction) {
	c.t.Helper()
	c.dist++
	resp := CombinerProcessUpdate(&CombinerSyncRequest{
		SenderID:       consentAgent,
		DeliveredBy:    consentAgent,
		Zone:           zone,
		DistributionID: fmt.Sprintf("consent-%04d", c.dist),
		Timestamp:      time.Now(),
		Operations:     ops,
		Publish:        publish,
	}, nil, map[string]bool{consentAgent: true}, c.hdb, nil)
	if resp.Status != "ok" {
		c.t.Fatalf("update for %s: status %q: %s (rejected %v)", zone, resp.Status, resp.Message, resp.RejectedItems)
	}
}

// sendKey is what the leader's agent sends when it is elected: its KEY and
// the publish instruction, here with at-ns.
func (c *consentCombiner) sendKey(zone string) {
	c.t.Helper()
	key := consentKey(zone)
	c.update(zone,
		[]core.RROperation{{Operation: "replace", RRtype: "KEY", Records: []string{key}}},
		&core.PublishInstruction{KEYRRs: []string{key}, Locations: []string{"at-apex", "at-ns"}})
}

// addNS is an NS change by the agent: one more of this provider's
// nameservers for the zone.
func (c *consentCombiner) addNS(zone, ns string) {
	c.t.Helper()
	c.update(zone, []core.RROperation{{Operation: "add", RRtype: "NS", Records: []string{fmt.Sprintf("%s 3600 IN NS %s", zone, ns)}}}, nil)
}

// signalKey says where a customer zone's KEY is, at the signal name under
// one nameserver: served in the provider zone, held as the agent's
// contribution to it, and in the persisted contributions a restart loads.
func (c *consentCombiner) signalKey(zone, ns string) (served, held, persisted bool) {
	c.t.Helper()
	owner := Sig0KeyOwnerName(zone, ns)
	prov, ok := Zones.Get(consentProviderZone)
	if !ok {
		c.t.Fatal("the provider zone is not configured")
	}
	if prov.HasPublishedData() {
		served = len(servedNames(c.t, prov.ZoneData, owner, dns.TypeKEY)) > 0
	}
	prov.Lock()
	if prov.MP != nil {
		held = len(prov.MP.AgentContributions[consentAgent][owner][dns.TypeKEY].RRs) > 0
	}
	prov.Unlock()
	all, err := LoadAllContributions(c.hdb)
	if err != nil {
		c.t.Fatalf("LoadAllContributions: %v", err)
	}
	persisted = len(all[consentProviderZone][consentAgent][owner][dns.TypeKEY].RRs) > 0
	return
}

func (c *consentCombiner) wantSignalKey(when, zone string, nameservers ...string) {
	c.t.Helper()
	for _, ns := range nameservers {
		if served, held, persisted := c.signalKey(zone, ns); !served || !held || !persisted {
			c.t.Errorf("%s: the KEY of %s under %s: served=%v held=%v persisted=%v, want it published", when, zone, ns, served, held, persisted)
		}
	}
}

func (c *consentCombiner) wantNoSignalKey(when, zone string, nameservers ...string) {
	c.t.Helper()
	for _, ns := range nameservers {
		if served, held, persisted := c.signalKey(zone, ns); served || held || persisted {
			c.t.Errorf("%s: the KEY of %s under %s: served=%v held=%v persisted=%v, want it nowhere", when, zone, ns, served, held, persisted)
		}
	}
}

// wantStored checks the stored instruction: its locations, the nameservers
// it has published under, and that the KEY is still in it.
func (c *consentCombiner) wantStored(when, zone string, locations, publishedNS []string) {
	c.t.Helper()
	stored, err := GetPublishInstruction(c.hdb, zone, consentAgent)
	if err != nil || stored == nil {
		c.t.Fatalf("%s: stored instruction for %s: %v, err=%v", when, zone, stored, err)
	}
	if fmt.Sprint(stored.Locations) != fmt.Sprint(locations) {
		c.t.Errorf("%s: stored locations for %s: %v, want %v", when, zone, stored.Locations, locations)
	}
	if fmt.Sprint(stored.PublishedNS) != fmt.Sprint(publishedNS) {
		c.t.Errorf("%s: stored published nameservers for %s: %v, want %v", when, zone, stored.PublishedNS, publishedNS)
	}
	if len(stored.KEYRRs) != 1 || stored.KEYRRs[0] != consentKey(zone) {
		c.t.Errorf("%s: the stored KEY for %s: %v", when, zone, stored.KEYRRs)
	}
}

// wantApexKey: the at-apex half of the instruction is not touched by any of
// this.
func (c *consentCombiner) wantApexKey(when string, mpzd *MPZoneData) {
	c.t.Helper()
	if got := servedNames(c.t, mpzd.ZoneData, mpzd.ZoneName, dns.TypeKEY); len(got) != 1 {
		c.t.Errorf("%s: the KEY at the apex of %s: %v, want the one KEY", when, mpzd.ZoneName, got)
	}
}

// The customer takes pubkey away after the instruction was stored, and the
// agent sends no new one. The next NS change publishes nothing under the new
// nameserver, retracts the names published before, the owner's nameserver
// among them, and leaves the instruction apex-only. An agent that still asks
// for at-ns gets the same.
func TestAnNSChangeWithdrawsTheSignalKeysOfAZoneWithoutPubkey(t *testing.T) {
	const zone = "resync.customer.example."
	c := newConsentCombiner(t)
	c.start(consentProviderZone, zone)
	c.load(consentProviderZone, consentProviderText())
	cust := c.load(zone, consentCustomerText(zone, true))

	// With pubkey: the instruction publishes under the owner's nameserver,
	// and an NS change under the new one.
	c.sendKey(zone)
	c.wantSignalKey("instruction, with pubkey", zone, consentNS1)
	c.addNS(zone, consentNS2)
	c.wantSignalKey("NS change, with pubkey", zone, consentNS1, consentNS2)
	c.wantStored("NS change, with pubkey", zone, []string{"at-apex", "at-ns"}, []string{consentNS1, consentNS2})

	c.ownerSays(cust, false)
	c.addNS(zone, consentNS3)
	c.wantNoSignalKey("NS change, pubkey withdrawn", zone, consentNS1, consentNS2, consentNS3)
	c.wantStored("NS change, pubkey withdrawn", zone, []string{"at-apex"}, nil)
	c.wantApexKey("NS change, pubkey withdrawn", cust)

	// It stays that way: a later change acts on nothing.
	c.addNS(zone, "ns4.alpha.example.")
	c.wantNoSignalKey("a later NS change", zone, consentNS1, consentNS2, consentNS3, "ns4.alpha.example.")

	// An agent that asks for at-ns whatever the zone says ends up apex-only.
	c.sendKey(zone)
	c.wantNoSignalKey("at-ns asked for without pubkey", zone, consentNS1, consentNS2, consentNS3)
	c.wantStored("at-ns asked for without pubkey", zone, []string{"at-apex"}, nil)
	c.wantApexKey("at-ns asked for without pubkey", cust)

	// The customer says pubkey again: the agent's next instruction publishes.
	c.ownerSays(cust, true)
	c.sendKey(zone)
	c.wantSignalKey("instruction, pubkey again", zone, consentNS1, consentNS2, consentNS3)
}

// The combiner starts with a stored at-ns instruction for a zone that does
// not say pubkey. Whichever of the two zones loads first, the startup
// re-apply ends with the signal name retracted, in the served provider zone,
// in the agent's contributions and in what the next start would load, and
// with the instruction apex-only. Until the customer's zone has loaded
// nothing is known of its consent, and nothing is touched.
func TestAStartWithdrawsTheSignalKeysOfAZoneWithoutPubkey(t *testing.T) {
	for _, order := range []string{"provider zone first", "customer zone first"} {
		t.Run(order, func(t *testing.T) {
			const zone = "start.customer.example."
			c := newConsentCombiner(t)
			c.start(consentProviderZone, zone)
			c.load(consentProviderZone, consentProviderText())
			c.load(zone, consentCustomerText(zone, true))
			c.sendKey(zone)
			c.wantSignalKey("before the restart", zone, consentNS1)

			// The restart. The provider zone's file was written with the
			// signal name in it; the customer's zone comes back without pubkey.
			signalRR := fmt.Sprintf("%s 3600 IN KEY 512 3 15 %s", Sig0KeyOwnerName(zone, consentNS1), testZSKPub)
			c.start(consentProviderZone, zone)
			var cust *MPZoneData
			if order == "provider zone first" {
				c.load(consentProviderZone, consentProviderText(signalRR))
				// The customer's zone has not loaded: as stored.
				c.wantSignalKey("provider zone loaded, customer zone not", zone, consentNS1)
				c.wantStored("provider zone loaded, customer zone not", zone, []string{"at-apex", "at-ns"}, []string{consentNS1})
				cust = c.load(zone, consentCustomerText(zone, false))
			} else {
				cust = c.load(zone, consentCustomerText(zone, false))
				// The provider zone has not loaded: there is nothing to
				// retract from yet, and the name stays in the instruction
				// for that zone's load to retract.
				c.wantStored("customer zone loaded, provider zone not", zone, []string{"at-apex", "at-ns"}, []string{consentNS1})
				c.load(consentProviderZone, consentProviderText(signalRR))
			}
			c.wantNoSignalKey("both zones loaded", zone, consentNS1)
			c.wantStored("both zones loaded", zone, []string{"at-apex"}, nil)
			c.wantApexKey("both zones loaded", cust)

			// And the provider zone's next publish does not bring it back.
			prov, _ := Zones.Get(consentProviderZone)
			if _, err := prov.CombineWithLocalChanges(); err != nil {
				t.Fatalf("CombineWithLocalChanges: %v", err)
			}
			c.wantNoSignalKey("the provider zone's next publish", zone, consentNS1)
		})
	}
}

// Consent is each zone's own. Two customers have signal names in the same
// provider zone and one of them takes pubkey away: through an NS change, a
// restart and a re-apply the other's names stay published and its
// instruction stays as it was, while the first one's are gone.
func TestAZoneThatSaysPubkeyKeepsItsSignalKeys(t *testing.T) {
	const says, lacks = "says.customer.example.", "lacks.customer.example."
	c := newConsentCombiner(t)
	c.start(consentProviderZone, says, lacks)
	c.load(consentProviderZone, consentProviderText())
	c.load(says, consentCustomerText(says, true))
	lacking := c.load(lacks, consentCustomerText(lacks, true))
	c.sendKey(says)
	c.sendKey(lacks)
	c.wantSignalKey("instruction", says, consentNS1)
	c.wantSignalKey("instruction", lacks, consentNS1)

	both := []string{consentNS1, consentNS2}
	c.ownerSays(lacking, false)
	c.addNS(says, consentNS2)
	c.addNS(lacks, consentNS2)
	c.wantSignalKey("NS change", says, both...)
	c.wantStored("NS change", says, []string{"at-apex", "at-ns"}, both)
	c.wantNoSignalKey("NS change", lacks, both...)
	c.wantStored("NS change", lacks, []string{"at-apex"}, nil)

	// A restart: the consenting zone's names are served again and its
	// instruction is as it was (the start itself is the subject of
	// combiner_signal_restart_test.go).
	c.start(consentProviderZone, says, lacks)
	prov := c.load(consentProviderZone, consentProviderText())
	c.load(says, consentCustomerText(says, true))
	c.load(lacks, consentCustomerText(lacks, false))
	c.wantStored("restart", says, []string{"at-apex", "at-ns"}, both)
	c.wantSignalKey("restart", says, both...)
	c.wantNoSignalKey("restart", lacks, both...)

	// A re-apply of the provider zone serves the consenting zone's names
	// and none of the other's.
	if _, err := CombinerReapplyContributions(consentProviderZone, c.hdb); err != nil {
		t.Fatalf("CombinerReapplyContributions: %v", err)
	}
	c.wantSignalKey("re-apply", says, both...)
	c.wantStored("re-apply", says, []string{"at-apex", "at-ns"}, both)
	c.wantNoSignalKey("re-apply", lacks, both...)
	if got := servedNames(t, prov.ZoneData, consentProviderZone, dns.TypeNS); len(got) != 1 {
		t.Errorf("the provider zone's own NS RRset after all this: %v", got)
	}
}

// The operator's re-apply of a provider zone reads the stored instructions
// too. For a zone that has lost pubkey since, it retracts instead of putting
// the signal name back from the persisted contributions.
func TestAReapplyWithdrawsTheSignalKeysOfAZoneWithoutPubkey(t *testing.T) {
	const zone = "reapply.customer.example."
	c := newConsentCombiner(t)
	c.start(consentProviderZone, zone)
	c.load(consentProviderZone, consentProviderText())
	cust := c.load(zone, consentCustomerText(zone, true))
	c.sendKey(zone)

	if _, err := CombinerReapplyContributions(consentProviderZone, c.hdb); err != nil {
		t.Fatalf("CombinerReapplyContributions: %v", err)
	}
	c.wantSignalKey("re-apply, with pubkey", zone, consentNS1)
	c.wantStored("re-apply, with pubkey", zone, []string{"at-apex", "at-ns"}, []string{consentNS1})

	c.ownerSays(cust, false)
	if _, err := CombinerReapplyContributions(consentProviderZone, c.hdb); err != nil {
		t.Fatalf("CombinerReapplyContributions: %v", err)
	}
	c.wantNoSignalKey("re-apply, pubkey withdrawn", zone, consentNS1)
	c.wantStored("re-apply, pubkey withdrawn", zone, []string{"at-apex"}, nil)

	// The customer zone's own re-apply still finds the at-apex half.
	if _, err := CombinerReapplyContributions(zone, c.hdb); err != nil {
		t.Fatalf("CombinerReapplyContributions(%s): %v", zone, err)
	}
	c.wantApexKey("re-apply of the customer zone", cust)
	c.wantNoSignalKey("re-apply of the customer zone", zone, consentNS1)
}

// A retraction that fails is not booked as done. The provider zone could not
// be published when the customer's consent was found missing: the signal
// name stays in the stored instruction, and at-ns with it, so the next use of
// the instruction tries again, and then the name is retracted.
func TestAWithdrawalThatFailsIsTriedAgain(t *testing.T) {
	const zone = "retry.customer.example."
	c := newConsentCombiner(t)
	c.start(consentProviderZone, zone)
	prov := c.load(consentProviderZone, consentProviderText())
	cust := c.load(zone, consentCustomerText(zone, true))
	c.sendKey(zone)
	c.wantSignalKey("with pubkey", zone, consentNS1)

	// The customer takes pubkey away while the provider zone cannot be
	// published: a zone store the combine does not write to.
	c.ownerSays(cust, false)
	store := prov.ZoneStore
	prov.ZoneStore = tdns.XfrZone
	c.addNS(zone, consentNS2)
	prov.ZoneStore = store
	if served, _, _ := c.signalKey(zone, consentNS1); !served {
		t.Fatal("the provider zone was published without the KEY: the retraction did not fail, and the test shows nothing")
	}
	c.wantStored("the retraction failed", zone, []string{"at-apex", "at-ns"}, []string{consentNS1})

	// The next use of the instruction tries again, and the publish that
	// was owed is made.
	c.addNS(zone, consentNS3)
	c.wantNoSignalKey("the retraction tried again", zone, consentNS1)
	c.wantStored("the retraction tried again", zone, []string{"at-apex"}, nil)
	c.wantApexKey("the retraction tried again", cust)
}

// A retraction whose save fails takes the KEY out of memory and keeps the
// name for a retry. The retry finds nothing left to take out. It must still
// save, or the saved KEY outlives the withdrawal: booked as done in the
// instruction, it comes back at the next start with nothing to withdraw it.
func TestAWithdrawalWhoseSaveFailedIsSavedOnTheRetry(t *testing.T) {
	const zone = "savefail.customer.example."
	c := newConsentCombiner(t)
	c.start(consentProviderZone, zone)
	prov := c.load(consentProviderZone, consentProviderText())
	cust := c.load(zone, consentCustomerText(zone, true))
	c.sendKey(zone)
	c.wantSignalKey("with pubkey", zone, consentNS1)

	// The customer takes pubkey away while the contributions cannot be saved.
	c.ownerSays(cust, false)
	prov.Lock()
	save := prov.MP.PersistContributions
	prov.MP.PersistContributions = func(string, string, map[string]map[uint16]core.RRset) error {
		return errors.New("the database is away")
	}
	prov.Unlock()
	c.addNS(zone, consentNS2)
	prov.Lock()
	prov.MP.PersistContributions = save
	prov.Unlock()
	if _, held, persisted := c.signalKey(zone, consentNS1); held || !persisted {
		t.Fatalf("the save did not fail as the test needs: held=%v persisted=%v, want held=false persisted=true", held, persisted)
	}
	c.wantStored("the save failed", zone, []string{"at-apex", "at-ns"}, []string{consentNS1})

	// The retry finds nothing in memory to take out, and saves all the same.
	c.addNS(zone, consentNS3)
	c.wantNoSignalKey("the retraction tried again", zone, consentNS1)
	c.wantStored("the retraction tried again", zone, []string{"at-apex"}, nil)
}

// The operator's re-apply finds a zone without pubkey and retracts its signal
// name, and the retraction fails: the name stays in the stored instruction,
// with at-ns, to be tried again. The same re-apply then reads the
// instructions to put the signal names back. It must not put back the one it
// has just failed to take away.
func TestAReapplyDoesNotPutBackAWithdrawalThatFailed(t *testing.T) {
	const zone = "reapplyfail.customer.example."
	c := newConsentCombiner(t)
	c.start(consentProviderZone, zone)
	prov := c.load(consentProviderZone, consentProviderText())
	cust := c.load(zone, consentCustomerText(zone, true))
	c.sendKey(zone)
	c.wantSignalKey("with pubkey", zone, consentNS1)

	// The customer takes pubkey away, and the re-apply runs while the
	// provider zone cannot be published.
	c.ownerSays(cust, false)
	store := prov.ZoneStore
	prov.ZoneStore = tdns.XfrZone
	_, _ = CombinerReapplyContributions(consentProviderZone, c.hdb)
	prov.ZoneStore = store
	c.wantStored("the retraction failed", zone, []string{"at-apex", "at-ns"}, []string{consentNS1})
	if _, held, persisted := c.signalKey(zone, consentNS1); held || persisted {
		t.Errorf("after a re-apply whose retraction failed: the KEY of %s under %s is held=%v persisted=%v, want it not put back", zone, consentNS1, held, persisted)
	}

	// The next re-apply tries the retraction again and finishes it.
	if _, err := CombinerReapplyContributions(consentProviderZone, c.hdb); err != nil {
		t.Fatalf("CombinerReapplyContributions: %v", err)
	}
	c.wantNoSignalKey("the retraction tried again", zone, consentNS1)
	c.wantStored("the retraction tried again", zone, []string{"at-apex"}, nil)
}

// The stored instructions could not be read when the combiner registered its
// first-load callbacks, and can be read by the time the zones load. The
// provider zone's re-apply reads them for itself and puts the signal name
// back. The customer zone's first load must still find the instruction and
// withdraw it, though the registration could not know the zone had one.
func TestAStartThatCouldNotReadTheInstructionsStillAsksForConsent(t *testing.T) {
	const zone = "unread.customer.example."
	c := newConsentCombiner(t)
	c.start(consentProviderZone, zone)
	c.load(consentProviderZone, consentProviderText())
	c.load(zone, consentCustomerText(zone, true))
	c.sendKey(zone)
	c.wantSignalKey("before the restart", zone, consentNS1)

	// The restart, with the instructions' table out of reach while the
	// callbacks are registered.
	rename := func(from, to string) {
		t.Helper()
		if _, err := c.hdb.DB.Exec("ALTER TABLE " + from + " RENAME TO " + to); err != nil {
			t.Fatalf("renaming %s: %v", from, err)
		}
	}
	rename("CombinerPublishInstructions", "CombinerPublishInstructionsAway")
	c.start(consentProviderZone, zone)
	rename("CombinerPublishInstructionsAway", "CombinerPublishInstructions")

	signalRR := fmt.Sprintf("%s 3600 IN KEY 512 3 15 %s", Sig0KeyOwnerName(zone, consentNS1), testZSKPub)
	c.load(consentProviderZone, consentProviderText(signalRR))
	c.wantSignalKey("provider zone loaded, customer zone not", zone, consentNS1)
	cust := c.load(zone, consentCustomerText(zone, false))
	c.wantNoSignalKey("both zones loaded", zone, consentNS1)
	c.wantStored("both zones loaded", zone, []string{"at-apex"}, nil)
	c.wantApexKey("both zones loaded", cust)
}

// The operator's re-apply withdraws the signal name of a zone without
// pubkey, and the save of that fails: the KEY is out of memory and still in
// the saved contributions. The re-apply's next step reloads those, KEY and
// all. It must take the name out again rather than serve it: a re-apply
// does not publish a KEY the customer has withdrawn. The name stays in the
// instruction, and a re-apply once the database is back finishes the
// withdrawal.
func TestAReapplyWhoseSaveFailsServesNoWithdrawnSignalKey(t *testing.T) {
	const zone = "reapplysave.customer.example."
	c := newConsentCombiner(t)
	c.start(consentProviderZone, zone)
	prov := c.load(consentProviderZone, consentProviderText())
	cust := c.load(zone, consentCustomerText(zone, true))
	c.sendKey(zone)
	c.wantSignalKey("with pubkey", zone, consentNS1)

	c.ownerSays(cust, false)
	prov.Lock()
	save := prov.MP.PersistContributions
	prov.MP.PersistContributions = func(string, string, map[string]map[uint16]core.RRset) error {
		return errors.New("the database is away")
	}
	prov.Unlock()
	_, _ = CombinerReapplyContributions(consentProviderZone, c.hdb)
	prov.Lock()
	prov.MP.PersistContributions = save
	prov.Unlock()
	if served, held, persisted := c.signalKey(zone, consentNS1); served || held || !persisted {
		t.Errorf("after a re-apply whose save failed: served=%v held=%v persisted=%v, want served=false held=false persisted=true", served, held, persisted)
	}
	c.wantStored("the save failed", zone, []string{"at-apex", "at-ns"}, []string{consentNS1})

	if _, err := CombinerReapplyContributions(consentProviderZone, c.hdb); err != nil {
		t.Fatalf("CombinerReapplyContributions: %v", err)
	}
	c.wantNoSignalKey("a re-apply once the database is back", zone, consentNS1)
	c.wantStored("a re-apply once the database is back", zone, []string{"at-apex"}, nil)
}

// A provider zone configured without the multi-provider option gets none of
// what the combiner does for a provider zone at a start and a refresh. The
// start says so: the zones are named, and a provider zone with the option is
// not.
func TestAProviderZoneWithoutTheMultiProviderOptionIsNamed(t *testing.T) {
	RegisterProviderZoneRRtypes(ProviderZoneConf{Zone: "plain.provider.example.", AllowedRRtypes: []string{"KEY"}})
	RegisterProviderZoneRRtypes(ProviderZoneConf{Zone: "mp.provider.example.", AllowedRRtypes: []string{"KEY"}})
	t.Cleanup(func() {
		delete(providerZoneRRtypes, "plain.provider.example.")
		delete(providerZoneRRtypes, "mp.provider.example.")
	})
	got := providerZonesWithoutOption([]string{"mp.provider.example", "customer.example."})
	found := map[string]bool{}
	for _, z := range got {
		found[z] = true
	}
	if !found["plain.provider.example."] || found["mp.provider.example."] {
		t.Errorf("provider zones without the option: %v, want plain.provider.example. and not mp.provider.example.", got)
	}
}
