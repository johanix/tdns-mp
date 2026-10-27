/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	tdnsmp "github.com/johanix/tdns-mp/v2"
	tdns "github.com/johanix/tdns/v2"
	"github.com/ryanuber/columnize"
)

// SendMPListCommand posts to /zone/mplist and returns the parsed response.
func SendMPListCommand(api *tdns.ApiClient) (tdnsmp.MPListResponse, error) {
	var resp tdnsmp.MPListResponse
	bytebuf := new(bytes.Buffer)
	if err := json.NewEncoder(bytebuf).Encode(struct{}{}); err != nil {
		return resp, fmt.Errorf("error encoding request: %v", err)
	}

	_, buf, err := api.Post("/zone/mplist", bytebuf.Bytes())
	if err != nil {
		return resp, fmt.Errorf("error from api post: %v", err)
	}

	if err := json.Unmarshal(buf, &resp); err != nil {
		return resp, fmt.Errorf("error from json.Unmarshal: %v json: %q", err, string(buf))
	}

	if resp.Error {
		return resp, fmt.Errorf("%s", resp.ErrorMsg)
	}

	return resp, nil
}

// ListMPZones displays multi-provider zone details in tabular format.
func ListMPZones(resp tdnsmp.MPListResponse) {
	if len(resp.MPZones) == 0 {
		fmt.Println("No multi-provider zones configured")
		return
	}

	var out, ownerErrors []string
	out = append(out, "Zone|Serial|Digest|Servers|Signers|Auditors|NSmgmt|ParentSync|Suffix|Options")

	var znames []string
	for zname := range resp.MPZones {
		znames = append(znames, zname)
	}
	sort.Strings(znames)

	for _, zname := range znames {
		info := resp.MPZones[zname]
		servers := strings.Join(info.Servers, ",")
		if servers == "" {
			servers = "(none)"
		}
		signers := strings.Join(info.Signers, ",")
		if signers == "" {
			signers = "(none)"
		}
		auditors := strings.Join(info.Auditors, ",")
		if auditors == "" {
			auditors = "(none)"
		}
		opts := []string{}
		for _, opt := range info.Options {
			opts = append(opts, tdns.ZoneOptionToString[opt])
		}
		sort.Strings(opts)
		optStr := "[" + strings.Join(opts, " ") + "]"
		// A zone with an active error (e.g. a failed inbound transfer) has no
		// usable participant data; flag it in the Options cell. Full message
		// is in `zone list`.
		if info.ZoneError != "" {
			optStr = "ERROR"
		}
		// The copy's instructions: its serial and digest, or ERR with the
		// owner error listed below the table.
		serial, digest := fmt.Sprint(info.Serial), info.Digest
		switch {
		case info.OwnerError != "":
			serial, digest = "ERR", "-"
			ownerErrors = append(ownerErrors, fmt.Sprintf("  %s: %s", zname, info.OwnerError))
		case digest == "":
			serial, digest = "-", "-"
		}
		out = append(out, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
			zname, serial, digest, servers, signers, auditors, info.NSmgmt, info.ParentSync, info.Suffix, optStr))
	}

	fmt.Println(columnize.SimpleFormat(out))
	if len(ownerErrors) > 0 {
		fmt.Println("Owner errors in the zone's instructions:")
		fmt.Println(strings.Join(ownerErrors, "\n"))
	}
}
