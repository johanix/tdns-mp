package tdnsmp

import (
	"testing"

	"github.com/miekg/dns"
)

// tdns-mp #171: after a start the provider zone serves the _signal KEYs its
// stored instructions say it has published, with no update from an agent and
// no re-apply by the operator. The zone comes back from its source without
// them: the combiner's writes are neither in the zone file nor in the
// upstream's copy. The tests use the consent tests' combiner
// (combiner_signal_consent_test.go): the agent's updates through
// CombinerProcessUpdate, a start through RegisterCombinerOnFirstLoad and the
// first-load callbacks it attaches.

// restartOrders are the two orders the zones of a start can load in.
var restartOrders = []string{"provider zone first", "customer zone first"}

// consentProviderSerial is the SOA serial in consentProviderText: what the
// provider zone serves when it has loaded and nothing has been published.
const consentProviderSerial = 1

// The combiner restarts with a stored at-ns instruction for a zone that says
// pubkey, and nothing else happens. Whichever of the two zones loads first,
// the signal names are served again, under the owner's nameserver and under
// the one the agent added, in one publish of the provider zone.
func TestAStartServesTheStoredSignalKeys(t *testing.T) {
	for _, order := range restartOrders {
		t.Run(order, func(t *testing.T) {
			const zone = "restart.customer.example."
			both := []string{consentNS1, consentNS2}
			c := newConsentCombiner(t)
			c.start(consentProviderZone, zone)
			c.load(consentProviderZone, consentProviderText())
			c.load(zone, consentCustomerText(zone, true))
			c.sendKey(zone)
			c.addNS(zone, consentNS2)
			c.wantSignalKey("before the restart", zone, both...)

			// The restart. The provider zone's source has none of the signal
			// names.
			c.start(consentProviderZone, zone)
			var prov, cust *MPZoneData
			if order == "provider zone first" {
				prov = c.load(consentProviderZone, consentProviderText())
				// The customer's zone has not loaded and says nothing of its
				// consent: the provider zone is as the instruction has it.
				c.wantSignalKey("provider zone loaded, customer zone not", zone, both...)
				cust = c.load(zone, consentCustomerText(zone, true))
			} else {
				cust = c.load(zone, consentCustomerText(zone, true))
				prov = c.load(consentProviderZone, consentProviderText())
			}
			c.wantSignalKey("after the restart", zone, both...)
			c.wantStored("after the restart", zone, []string{"at-apex", "at-ns"}, both)
			c.wantApexKey("after the restart", cust)
			if got := servedNames(t, prov.ZoneData, consentProviderZone, dns.TypeNS); len(got) != 1 {
				t.Errorf("the provider zone's own NS RRset after the restart: %v", got)
			}

			// One publish for the whole re-apply, and none after it: a second
			// pass over the same state finds the zone as it should be.
			if serial := servedSerial(t, prov.ZoneData, consentProviderZone); serial != consentProviderSerial+1 {
				t.Errorf("the provider zone's serial after the restart: %d, want one publish after its source's %d", serial, consentProviderSerial)
			}
			if changed, err := prov.CombineWithLocalChanges(); err != nil || changed {
				t.Errorf("the provider zone's next publish: changed=%v err=%v, want nothing to do", changed, err)
			}
			c.wantSignalKey("the provider zone's next publish", zone, both...)
		})
	}
}

// Two customers have signal names in the same provider zone, and one of them
// comes back from the restart without pubkey. The start serves the names of
// the one that consents and none of the other's, whichever zone loads first,
// and the other's instruction ends apex-only.
func TestAStartServesNoSignalKeyWithoutConsent(t *testing.T) {
	for _, order := range restartOrders {
		t.Run(order, func(t *testing.T) {
			const says, lacks = "says.restart.example.", "lacks.restart.example."
			c := newConsentCombiner(t)
			c.start(consentProviderZone, says, lacks)
			c.load(consentProviderZone, consentProviderText())
			c.load(says, consentCustomerText(says, true))
			c.load(lacks, consentCustomerText(lacks, true))
			c.sendKey(says)
			c.sendKey(lacks)
			c.wantSignalKey("before the restart", says, consentNS1)
			c.wantSignalKey("before the restart", lacks, consentNS1)

			c.start(consentProviderZone, says, lacks)
			var prov *MPZoneData
			if order == "provider zone first" {
				prov = c.load(consentProviderZone, consentProviderText())
				// Neither customer zone has loaded: both instructions are as
				// stored, and so is what the provider zone serves.
				c.wantSignalKey("provider zone loaded, customer zones not", says, consentNS1)
				c.wantSignalKey("provider zone loaded, customer zones not", lacks, consentNS1)
				c.load(says, consentCustomerText(says, true))
				c.load(lacks, consentCustomerText(lacks, false))
			} else {
				c.load(says, consentCustomerText(says, true))
				c.load(lacks, consentCustomerText(lacks, false))
				prov = c.load(consentProviderZone, consentProviderText())
				// The zone without consent was known when the provider zone
				// loaded: its name was never published, not even for the time
				// between two publishes. One publish, with the other's name.
				if serial := servedSerial(t, prov.ZoneData, consentProviderZone); serial != consentProviderSerial+1 {
					t.Errorf("the provider zone's serial after its load: %d, want one publish after its source's %d", serial, consentProviderSerial)
				}
			}
			c.wantSignalKey("after the restart", says, consentNS1)
			c.wantStored("after the restart", says, []string{"at-apex", "at-ns"}, []string{consentNS1})
			c.wantNoSignalKey("after the restart", lacks, consentNS1)
			c.wantStored("after the restart", lacks, []string{"at-apex"}, nil)

			// And the provider zone's next publish does not bring it back.
			if _, err := prov.CombineWithLocalChanges(); err != nil {
				t.Fatalf("CombineWithLocalChanges: %v", err)
			}
			c.wantSignalKey("the provider zone's next publish", says, consentNS1)
			c.wantNoSignalKey("the provider zone's next publish", lacks, consentNS1)
		})
	}
}
