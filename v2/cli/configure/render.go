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
	"text/template"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

type renderCtx struct {
	Global   GlobalValues
	Agent    AgentValues
	Signer   SignerValues
	Combiner CombinerValues

	Paths rolePaths

	// *Listen are bind targets (use InternalIP). *Dial are the
	// addresses each role uses to reach its peers; same host as
	// the bind, so they coincide with the listen addresses on a
	// single-host deployment.
	AgentDnsListen    string
	AgentApiListen    string
	SignerDnsListen   string
	SignerDnsListen53 string
	SignerApiListen   string
	CombinerDnsListen string
	CombinerApiListen string

	// *PublicListen are bind targets that should be reachable from
	// outside the host (e.g. mpcli base URLs published in the
	// generated mpcli config). Built from PublicIP.
	AgentApiPublic    string
	SignerApiPublic   string
	CombinerApiPublic string
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
	return p
}

func makeRenderCtx(cv CoordinatedValues) renderCtx {
	internal := cv.Global.InternalIP
	public := cv.Global.PublicIP
	hpInternal := func(port int) string {
		return net.JoinHostPort(internal, strconv.Itoa(port))
	}
	hpPublic := func(port int) string {
		return net.JoinHostPort(public, strconv.Itoa(port))
	}
	return renderCtx{
		Global:            cv.Global,
		Agent:             cv.Agent,
		Signer:            cv.Signer,
		Combiner:          cv.Combiner,
		Paths:             makeRolePaths(cv.Global.KeysDir, cv.Global.CertsDir),
		AgentDnsListen:    hpInternal(agentDnsPort),
		AgentApiListen:    hpInternal(agentApiPort),
		SignerDnsListen:   hpInternal(signerDnsPort),
		SignerDnsListen53: hpInternal(signerDns53Port),
		SignerApiListen:   hpInternal(signerApiPort),
		CombinerDnsListen: hpInternal(combinerDnsPort),
		CombinerApiListen: hpInternal(combinerApiPort),
		AgentApiPublic:    hpPublic(agentApiPort),
		SignerApiPublic:   hpPublic(signerApiPort),
		CombinerApiPublic: hpPublic(combinerApiPort),
	}
}

// renderAll produces the rendered YAML for each config file,
// keyed by its filesystem path.
func renderAll(cv CoordinatedValues) (map[string]string, error) {
	ctx := makeRenderCtx(cv)

	pairs := []struct {
		path string
		tmpl string
	}{
		{pathMpagent, "templates/mpagent.yaml.tmpl"},
		{pathMpsigner, "templates/mpsigner.yaml.tmpl"},
		{pathMpcombiner, "templates/mpcombiner.yaml.tmpl"},
		{pathMpcli, "templates/mpcli.yaml.tmpl"},
	}

	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		raw, err := templateFS.ReadFile(p.tmpl)
		if err != nil {
			return nil, fmt.Errorf("read embedded %s: %w", p.tmpl, err)
		}
		t, err := template.New(p.tmpl).Option("missingkey=error").Parse(string(raw))
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p.tmpl, err)
		}
		var buf bytes.Buffer
		if err := t.Execute(&buf, ctx); err != nil {
			return nil, fmt.Errorf("render %s: %w", p.tmpl, err)
		}
		out[p.path] = buf.String()
	}
	return out, nil
}
