/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Configurator: template rendering.
 *
 * Templates live under cmd/mpcli/templates/ and are embedded at
 * build time. The render context exposes the coordinated role
 * values plus a derived block of per-role file paths computed
 * from the global keys/certs directories.
 */
package main

import (
	"bytes"
	"embed"
	"fmt"
	"path/filepath"
	"text/template"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// renderCtx is the struct templates see. Fields are organised by
// role + a Paths block with all derived file paths and explicit
// listen-address fields computed from Global.PublicIP + built-in
// ports, so templates never have to do string manipulation.
type renderCtx struct {
	Global   GlobalValues
	Agent    AgentValues
	Signer   SignerValues
	Combiner CombinerValues

	Paths rolePaths

	// Derived listen addresses (all on Global.PublicIP).
	AgentDnsListen    string // {ip}:8054
	AgentApiListen    string // {ip}:7054
	SignerDnsListen   string // {ip}:8053
	SignerDnsListen53 string // {ip}:53
	SignerApiListen   string // {ip}:7053
	CombinerDnsListen string // {ip}:8055
	CombinerApiListen string // {ip}:7055
}

// rolePaths is the per-role set of derived file paths. Filenames
// are deterministic: {role}.jose.priv.json / {role}.jose.pub.json
// under KeysDir, and {role}.crt / {role}.key under CertsDir.
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
	ip := cv.Global.PublicIP
	return renderCtx{
		Global:            cv.Global,
		Agent:             cv.Agent,
		Signer:            cv.Signer,
		Combiner:          cv.Combiner,
		Paths:             makeRolePaths(cv.Global.KeysDir, cv.Global.CertsDir),
		AgentDnsListen:    fmt.Sprintf("%s:%d", ip, agentDnsPort),
		AgentApiListen:    fmt.Sprintf("%s:%d", ip, agentApiPort),
		SignerDnsListen:   fmt.Sprintf("%s:%d", ip, signerDnsPort),
		SignerDnsListen53: fmt.Sprintf("%s:%d", ip, signerDns53Port),
		SignerApiListen:   fmt.Sprintf("%s:%d", ip, signerApiPort),
		CombinerDnsListen: fmt.Sprintf("%s:%d", ip, combinerDnsPort),
		CombinerApiListen: fmt.Sprintf("%s:%d", ip, combinerApiPort),
	}
}

// renderAll produces the rendered YAML for each of the four
// config files, keyed by final filesystem path.
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
