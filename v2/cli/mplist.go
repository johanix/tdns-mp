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

	var out []string
	out = append(out, "Zone|Servers|Signers|Auditors|NSmgmt|ParentSync|Suffix|Options")

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
		out = append(out, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
			zname, servers, signers, auditors, info.NSmgmt, info.ParentSync, info.Suffix, optStr))
	}

	fmt.Println(columnize.SimpleFormat(out))
}
