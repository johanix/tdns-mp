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

	tdnsmp "github.com/johanix/tdns-mp/v2"
	tdns "github.com/johanix/tdns/v2"
)

func main() {
	tdns.Globals.App.Type = tdnsmp.AppTypeMPAgent
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

	// MainInit skipped registering the default zone-based query
	// handler when no zones were declared in the config file. The
	// agent always creates an auto-zone later via SetupAgent, so
	// we need the handler regardless — register it ourselves in
	// the gap case to make the auto-zone reachable via DNS.
	if len(tdns.Conf.Zones) == 0 {
		if err := tdns.RegisterQueryHandler(0, tdns.DefaultQueryHandler); err != nil {
			tdns.Shutdowner(conf.Config, fmt.Sprintf("Error registering default query handler: %v", err))
		}
	}

	apirouter, err := conf.Config.SetupAPIRouter(ctx)
	if err != nil {
		tdns.Shutdowner(conf.Config, fmt.Sprintf("Error setting up API router: %v", err))
	}

	conf.SetupMPAgentRoutes(ctx, apirouter)

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
	err = conf.StartMPAgent(ctx, apirouter)
	if err != nil {
		tdns.Shutdowner(conf.Config, fmt.Sprintf("Error starting: %v", err))
	}

	// Enter main loop
	conf.Config.MainLoop(ctx, stop)
}
