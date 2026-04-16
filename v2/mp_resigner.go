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

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

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
	} else {
		lgSigner.Info("MPResignerEngine starting", "interval_sec", interval)
	}

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
			for _, mpzd := range ZonesToKeepSigned {
				if !mpzd.Options[tdns.OptInlineSigning] && !mpzd.Options[tdns.OptOnlineSigning] {
					continue
				}
				lgSigner.Debug("MPResignerEngine: re-signing zone", "zone", mpzd.ZoneName)
				newrrsigs, err := mpzd.SignZone(NewHsyncDB(mpzd.ZoneData.KeyDB), false)
				if err != nil {
					lgSigner.Error("MPResignerEngine: failed to re-sign zone", "zone", mpzd.ZoneName, "err", err)
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
	}

	return nil
}
