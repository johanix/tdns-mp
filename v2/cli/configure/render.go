/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * mpcli configure subpackage: template rendering.
 *
 * Templates live under templates/ and are embedded at build
 * time. The render context exposes the coordinated role values
 * plus a derived block of per-role file paths and listen
 * addresses computed from Global.KeysDir / CertsDir / PublicIP
 * + built-in ports, so templates never have to do string
 * manipulation.
 */
package configure

import (
	"bytes"
	"embed"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/miekg/dns"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// exampleZone is the zone every generated config carries, so that a
// fresh stack has data to move end to end: the combiner loads it from a
// zone file standing in for the zone owner, the signer signs it, and the
// agent (and the auditor) pull it.
const exampleZone = "mptest.example."

type renderCtx struct {
	Global   GlobalValues
	Agent    AgentValues
	Signer   SignerValues
	Combiner CombinerValues
	Auditor  AuditorValues

	Layout fsLayout
	Paths  rolePaths

	// *Dns* bind the wildcard of InternalIP's address family (0.0.0.0
	// or ::) because the DNS engine serves external clients and the
	// local interface IP isn't known here.
	// *Api* bind InternalIP (127.0.0.1 single-host) — management
	// API stays loopback-only for now; mpcli reaches it via SSH
	// tunnel or local invocation.
	// *Dial are the intra-component peer addresses each role uses
	// to talk to the others; InternalIP works for both same-host
	// (127.0.0.1) and multi-host (private IP) deployments.
	AgentDnsListen    string
	AgentApiListen    string
	AgentDnsDial      string
	SignerDnsListen   string
	SignerDnsListen53 string
	SignerApiListen   string
	SignerDnsDial     string
	CombinerDnsListen string
	CombinerApiListen string
	CombinerDnsDial   string
	AuditorDnsListen  string
	AuditorApiListen  string
	AuditorDnsDial    string

	// *SyncApiListen is where the agent and the auditor start their
	// agent-to-agent sync API (multi-provider.api). It binds InternalIP
	// and is not advertised to peers.
	AgentSyncApiListen   string
	AuditorSyncApiListen string

	// AgentDnsPort is the numeric port the agent's signaling DNS
	// service listens on. Used in the multi-provider.dns block of
	// the agent config, where `port:` and the port in `listen:`
	// must match what the listeners: block actually binds.
	AgentDnsPort       int
	AuditorDnsPort     int
	AgentSyncApiPort   int
	AuditorSyncApiPort int

	// InternalPrefix is InternalIP as a single-address prefix: the
	// downstreams: ACL that lets the local roles transfer zones from
	// each other.
	InternalPrefix string

	// ExampleZone and the HSYNC3 labels of its parties. PublicIPRRType
	// is A or AAAA, for the address records the example zone publishes.
	ExampleZone    string
	ProviderLabel  string
	AuditorLabel   string
	PublicIPRRType string
}

// rolePaths collects the deterministic per-role filenames.
type rolePaths struct {
	AgentJosePriv string
	AgentJosePub  string
	AgentCert     string
	AgentKey      string

	SignerJosePriv string
	SignerJosePub  string
	SignerCert     string
	SignerKey      string

	CombinerJosePriv string
	CombinerJosePub  string
	CombinerCert     string
	CombinerKey      string

	AuditorJosePriv string
	AuditorJosePub  string
	AuditorCert     string
	AuditorKey      string

	ExampleZoneFile string
}

func makeRolePaths(keysDir, certsDir string) rolePaths {
	jose := func(role string) (priv, pub string) {
		priv = filepath.Join(keysDir, role+".jose.priv.json")
		pub = filepath.Join(keysDir, role+".jose.pub.json")
		return
	}
	cert := func(role string) (crt, key string) {
		crt = filepath.Join(certsDir, role+".crt")
		key = filepath.Join(certsDir, role+".key")
		return
	}
	var p rolePaths
	p.AgentJosePriv, p.AgentJosePub = jose("agent")
	p.AgentCert, p.AgentKey = cert("agent")
	p.SignerJosePriv, p.SignerJosePub = jose("signer")
	p.SignerCert, p.SignerKey = cert("signer")
	p.CombinerJosePriv, p.CombinerJosePub = jose("combiner")
	p.CombinerCert, p.CombinerKey = cert("combiner")
	p.AuditorJosePriv, p.AuditorJosePub = jose("auditor")
	p.AuditorCert, p.AuditorKey = cert("auditor")
	return p
}

// providerLabel derives this provider's HSYNC3 label from the agent
// identity: "alpha" for agent.alpha.example., otherwise the identity's
// first label.
func providerLabel(agentIdentity string) string {
	labels := dns.SplitDomainName(agentIdentity)
	switch {
	case len(labels) == 0:
		return "provider"
	case len(labels) >= 2 && strings.EqualFold(labels[0], "agent"):
		return strings.ToLower(labels[1])
	default:
		return strings.ToLower(labels[0])
	}
}

// auditorLabel is the auditor's HSYNC3 label, kept distinct from the
// provider's.
func auditorLabel(provider string) string {
	if provider == "auditor" {
		return "audit"
	}
	return "auditor"
}

func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

func makeRenderCtx(cv CoordinatedValues, l fsLayout) renderCtx {
	internal := cv.Global.InternalIP
	hpInternal := func(port int) string {
		return net.JoinHostPort(internal, strconv.Itoa(port))
	}
	// The wildcard follows the family of InternalIP, which every role
	// dials: an IPv4 wildcard does not accept an IPv6 connection.
	wildcard := "0.0.0.0"
	if isIPv6(internal) {
		wildcard = "::"
	}
	hpAny := func(port int) string {
		return net.JoinHostPort(wildcard, strconv.Itoa(port))
	}
	prefix, rrtype := internal+"/32", "A"
	if isIPv6(internal) {
		prefix = internal + "/128"
	}
	if isIPv6(cv.Global.PublicIP) {
		rrtype = "AAAA"
	}
	provider := providerLabel(cv.Agent.Identity)
	paths := makeRolePaths(cv.Global.KeysDir, cv.Global.CertsDir)
	paths.ExampleZoneFile = l.exampleZoneFile()
	return renderCtx{
		Global:               cv.Global,
		Agent:                cv.Agent,
		Signer:               cv.Signer,
		Combiner:             cv.Combiner,
		Auditor:              cv.Auditor,
		Layout:               l,
		Paths:                paths,
		AgentDnsListen:       hpAny(agentDnsPort),
		AgentApiListen:       hpInternal(agentApiPort),
		AgentDnsDial:         hpInternal(agentDnsPort),
		SignerDnsListen:      hpAny(signerDnsPort),
		SignerDnsListen53:    hpAny(signerDns53Port),
		SignerApiListen:      hpInternal(signerApiPort),
		SignerDnsDial:        hpInternal(signerDnsPort),
		CombinerDnsListen:    hpAny(combinerDnsPort),
		CombinerApiListen:    hpInternal(combinerApiPort),
		CombinerDnsDial:      hpInternal(combinerDnsPort),
		AuditorDnsListen:     hpAny(auditorDnsPort),
		AuditorApiListen:     hpInternal(auditorApiPort),
		AuditorDnsDial:       hpInternal(auditorDnsPort),
		AgentSyncApiListen:   hpInternal(agentSyncApiPort),
		AuditorSyncApiListen: hpInternal(auditorSyncApiPort),
		AgentDnsPort:         agentDnsPort,
		AuditorDnsPort:       auditorDnsPort,
		AgentSyncApiPort:     agentSyncApiPort,
		AuditorSyncApiPort:   auditorSyncApiPort,
		InternalPrefix:       prefix,
		ExampleZone:          exampleZone,
		ProviderLabel:        provider,
		AuditorLabel:         auditorLabel(provider),
		PublicIPRRType:       rrtype,
	}
}

// renderAll produces the rendered YAML for each config file,
// keyed by its filesystem path.
func renderAll(cv CoordinatedValues) (map[string]string, error) {
	return renderAllIn(cv, defaultLayout)
}

// renderAllIn is renderAll for an explicit layout.
func renderAllIn(cv CoordinatedValues, l fsLayout) (map[string]string, error) {
	ctx := makeRenderCtx(cv, l)

	pairs := []struct {
		path string
		tmpl string
	}{
		{l.mpagent(), "templates/mpagent.yaml.tmpl"},
		{l.mpsigner(), "templates/mpsigner.yaml.tmpl"},
		{l.mpcombiner(), "templates/mpcombiner.yaml.tmpl"},
		{l.mpcli(), "templates/mpcli.yaml.tmpl"},
	}
	// Auditor is optional. Add its template only when the operator
	// opted in via the interview (signalled by a non-empty
	// Auditor.Identity).
	if cv.Auditor.Identity != "" {
		pairs = append(pairs, struct {
			path string
			tmpl string
		}{l.mpauditor(), "templates/mpauditor.yaml.tmpl"})
	}

	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		body, err := renderTemplate(p.tmpl, ctx)
		if err != nil {
			return nil, err
		}
		out[p.path] = body
	}
	return out, nil
}

// renderExampleZone renders the example zone's zone file.
func renderExampleZone(cv CoordinatedValues, l fsLayout) (string, error) {
	return renderTemplate("templates/mptest.example.zone.tmpl", makeRenderCtx(cv, l))
}

func renderTemplate(name string, ctx renderCtx) (string, error) {
	raw, err := templateFS.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("read embedded %s: %w", name, err)
	}
	t, err := template.New(name).Option("missingkey=error").Parse(string(raw))
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", name, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return "", fmt.Errorf("render %s: %w", name, err)
	}
	return buf.String(), nil
}
