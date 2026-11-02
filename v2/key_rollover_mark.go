package tdnsmp

import (
	"context"
	"time"
)

// rolloverMarkMaxAge is how long an agent rests on its signer's word that a
// rollover is under way before it asks again. A transition's next keys step
// and the thaw wait on that word with no time-out, and the signer says the
// rollover's end once (KeysChanged, MarksChanged): a push lost on the way, or
// an older one that lands after it (inventories are ordered as they come),
// would hold the zone until a key row is next written. A rollover really under
// way costs one request a minute for as long as it lasts.
const rolloverMarkMaxAge = time.Minute

// watchRolloverMarks asks the signer again for each zone whose mark is old,
// until ctx ends.
func (conf *Config) watchRolloverMarks(ctx context.Context, tm *MPTransportBridge) {
	ticker := time.NewTicker(rolloverMarkMaxAge / 4)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			conf.askOnOldRolloverMarks(now, func(mpzd *MPZoneData) {
				go conf.askForInventory(ctx, mpzd, tm)
			})
		}
	}
}

// askOnOldRolloverMarks calls ask for each zone whose signer's last word is a
// rollover, and that word is rolloverMarkMaxAge old at now.
func (conf *Config) askOnOldRolloverMarks(now time.Time, ask func(*MPZoneData)) {
	for _, zone := range conf.InternalMp.MPZoneNames {
		mpzd, ok := Zones.Get(zone)
		if !ok || mpzd == nil {
			continue
		}
		if inv := mpzd.GetLastKeyInventory(); inv != nil && inv.Rollover && now.Sub(inv.Received) >= rolloverMarkMaxAge {
			ask(mpzd)
		}
	}
}

// askForInventory is the own read's request (requestKeyInventory): the answer
// goes the way a pushed one goes, so that the zone's inventories are handled in
// the order they came (#210). With no answer the mark stays old, and the next
// tick asks again.
func (conf *Config) askForInventory(ctx context.Context, mpzd *MPZoneData, tm *MPTransportBridge) {
	qs := conf.InternalMp.MsgQs
	if inv := mpzd.requestKeyInventory(ctx, tm); inv != nil && qs != nil && qs.KeystateInventory != nil {
		qs.offerKeystateInventory(inv)
	}
}
