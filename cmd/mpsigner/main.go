/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/mattn/go-sqlite3"

	"github.com/johanix/dnssec-algorithms/mldsa44"
	"github.com/johanix/dnssec-algorithms/slhdsa128s"

	tdnsmp "github.com/johanix/tdns-mp/v2"
	tdns "github.com/johanix/tdns/v2"
	algs "github.com/johanix/tdns/v2/algorithms"
)

// Pure-Go PQ algorithms (CIRCL-backed) — always registered, so the
// signer can sign with and report them via "keystore dnssec
// algorithms". The liboqs-backed ones are not wired into mpsigner.
//
// tdns/v2 algorithms.Register now also takes the role capabilities
// (ForKSK/ForZSK, enforced by the DNSSEC policy check in large_ksk.go)
// and the static Facts. Both are copied from dnssec-algorithms
// registry/registry.go, which tdns's own binaries consume through the
// tdns-genalgs generator (cmdv2/genalgs + a per-app algs.list). NOTE:
// the codepoints below are tdns-mp's historical assignments and no
// longer match that registry (it has 200=MLDSA65, 202=SLHDSA128S);
// renumbering is a flag day for keys already in MPDnssecKeyStore and
// is deliberately NOT done here.
func init() {
	algs.Register(199, mldsa44.New(),
		algs.Capabilities{ForSIG0: true, ForDNSSEC: true, ForKSK: true},
		algs.Facts{PubKeyBytes: 1312, SigBytes: 2420, SecKeyBytes: 2560, SecurityLevel: 2, Maturity: "final", Description: "ML-DSA-44 (FIPS 204), lattice"})
	algs.Register(200, slhdsa128s.New(),
		algs.Capabilities{ForSIG0: true, ForDNSSEC: true, ForKSK: true},
		algs.Facts{PubKeyBytes: 32, SigBytes: 7856, SecKeyBytes: 64, SecurityLevel: 1, Maturity: "final", Description: "SLH-DSA-SHA2-128s (FIPS 205), hash-based; tiny keys, large slow signatures"})
}

func main() {
	tdns.Globals.App.Type = tdnsmp.AppTypeMPSigner
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Date = appDate

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conf := tdnsmp.Config{Config: &tdns.Conf}

	// DNS infrastructure + MP additions
	err := conf.MainInit(ctx, "")
	if err != nil {
		tdns.Shutdowner(conf.Config, fmt.Sprintf("Error initializing: %v", err))
	}

	apirouter, err := conf.Config.SetupAPIRouter(ctx)
	if err != nil {
		tdns.Shutdowner(conf.Config, fmt.Sprintf("Error setting up API router: %v", err))
	}

	// SIGHUP reload watcher
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if _, err := conf.Config.ReloadZoneConfig(ctx); err != nil {
					log.Printf("SIGHUP reload failed: %v", err)
				}
			}
		}
	}()

	// DNS engines + MP engines
	err = conf.StartMPSigner(ctx, apirouter)
	if err != nil {
		tdns.Shutdowner(conf.Config, fmt.Sprintf("Error starting: %v", err))
	}

	// Enter main loop
	conf.Config.MainLoop(ctx, stop)
}
