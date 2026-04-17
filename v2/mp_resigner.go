/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MP ResignerEngine and SetupZoneSigning for *MPZoneData.
 * Handles MP signer zones only. The tdns ResignerEngine
 * continues to handle non-MP zones and the agent auto-zone.
 */

package tdnsmp

import (
	"context"
	"fmt"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/viper"
)

// MPResignerEngine periodically re-signs MP zones. Runs alongside
// the tdns ResignerEngine, which handles non-MP zones.
func MPResignerEngine(ctx context.Context, resignch chan *MPZoneData) {
	interval := viper.GetInt("resignerengine.interval")
	if interval < 60 {
		interval = 60
	}
	if interval > 3600 {
		interval = 3600
	}

	if !viper.GetBool("service.resign") {
		lgSigner.Info("MPResignerEngine is NOT active, MP zones updated only on Notifies")
		for {
			select {
			case <-ctx.Done():
				lgSigner.Info("MPResignerEngine terminating (inactive mode)")
				return
			case _, ok := <-resignch:
				if !ok {
					return
				}
				continue
			}
		}
	}
	lgSigner.Info("MPResignerEngine starting", "interval_sec", interval)

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	ZonesToKeepSigned := make(map[string]*MPZoneData)

	for {
		select {
		case <-ctx.Done():
			lgSigner.Info("MPResignerEngine terminating")
			return
		case mpzd, ok := <-resignch:
			if !ok {
				return
			}
			if mpzd == nil {
				lgSigner.Warn("MPResignerEngine: nil zone data received")
				continue
			}
			if _, exist := ZonesToKeepSigned[mpzd.ZoneName]; !exist {
				lgSigner.Info("MPResignerEngine: adding zone to re-sign list", "zone", mpzd.ZoneName)
			}
			ZonesToKeepSigned[mpzd.ZoneName] = mpzd

		case <-ticker.C:
			for name, mpzd := range ZonesToKeepSigned {
				// Drop zones that have been removed from the
				// in-memory registry or that no longer opt into
				// signing — keeps the map bounded and releases
				// stale *MPZoneData references.
				current, exists := Zones.Get(name)
				if !exists || current == nil {
					lgSigner.Info("MPResignerEngine: dropping removed zone from re-sign list", "zone", name)
					delete(ZonesToKeepSigned, name)
					continue
				}
				if !current.Options[tdns.OptInlineSigning] && !current.Options[tdns.OptOnlineSigning] {
					lgSigner.Info("MPResignerEngine: dropping zone with signing disabled", "zone", name)
					delete(ZonesToKeepSigned, name)
					continue
				}
				// Use the fresh wrapper from the registry in case
				// the zone was refreshed; falls back to mpzd if
				// the two are the same object.
				if current != mpzd {
					mpzd = current
					ZonesToKeepSigned[name] = current
				}
				lgSigner.Debug("MPResignerEngine: re-signing zone", "zone", mpzd.ZoneName)
				newrrsigs, err := mpzd.SignZone(NewHsyncDB(mpzd.ZoneData.KeyDB), false)
				if err != nil {
					lgSigner.Error("MPResignerEngine: failed to re-sign zone", "zone", mpzd.ZoneName, "err", err)
					continue
				}
				lgSigner.Info("MPResignerEngine: zone re-signed", "zone", mpzd.ZoneName, "new_rrsigs", newrrsigs)
			}
		}
	}
}

// SetupZoneSigning performs initial signing for an MP zone and
// sends it to the MP ResignerEngine for periodic re-signing.
func (mpzd *MPZoneData) SetupZoneSigning(resignq chan<- *MPZoneData) error {
	zd := mpzd.ZoneData

	if !zd.Options[tdns.OptOnlineSigning] && !zd.Options[tdns.OptInlineSigning] {
		return nil
	}

	if zd.ZoneType != tdns.Primary && !zd.Options[tdns.OptInlineSigning] {
		return nil
	}

	kdb := zd.KeyDB
	newrrsigs, err := mpzd.SignZone(NewHsyncDB(kdb), false)
	if err != nil {
		lg.Error("MP SetupZoneSigning: SignZone failed", "zone", zd.ZoneName, "err", err)
		return err
	}

	lg.Info("MP SetupZoneSigning: zone signed", "zone", zd.ZoneName, "newRRSIGs", newrrsigs)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	select {
	case resignq <- mpzd:
	case <-ctx.Done():
		lg.Error("MP SetupZoneSigning: timeout sending zone to resign queue", "zone", zd.ZoneName)
		return fmt.Errorf("MP SetupZoneSigning: timeout enqueuing zone %q for periodic re-signing", zd.ZoneName)
	}

	return nil
}
