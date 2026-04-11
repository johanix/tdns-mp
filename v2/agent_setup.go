/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/johanix/tdns-transport/v2/crypto/jose"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (conf *Config) SetupAgentAutoZone(zonename string) (*tdns.ZoneData, error) {
	lgAgent.Info("creating a minimal auto zone", "zone", zonename)

	var zd *tdns.ZoneData
	var err error
	if len(conf.Config.MultiProvider.Local.Nameservers) > 0 {
		nsNames := make([]string, len(conf.Config.MultiProvider.Local.Nameservers))
		for i, ns := range conf.Config.MultiProvider.Local.Nameservers {
			nsNames[i] = dns.Fqdn(ns)
		}
		zd, err = conf.Config.Internal.KeyDB.CreateAutoZone(zonename, nil, nsNames)
	} else {
		addrs, findErr := conf.Config.FindDnsEngineAddrs()
		if findErr != nil {
			return nil, fmt.Errorf("SetupAgentAutoZone: failed to find nameserver addresses: %v", findErr)
		}
		zd, err = conf.Config.Internal.KeyDB.CreateAutoZone(zonename, addrs, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("SetupAgentAutoZone: failed to create minimal auto zone for agent identity %q: %v", zonename, err)
	}
	zd.Options[tdns.OptAllowUpdates] = true
	// TODO: zd.SyncQ assignment skipped — tdns.SyncRequest vs local SyncRequest type mismatch.
	// This will be resolved when SyncRequest becomes an alias or when zd.SyncQ is removed from tdns.

	// Check for local notify configuration and set downstream targets
	if len(conf.Config.MultiProvider.Local.Notify) > 0 {
		zd.Downstreams = tdns.NormalizeAddresses(conf.Config.MultiProvider.Local.Notify)
		lgAgent.Debug("setting downstream notify targets", "zone", zonename, "downstreams", zd.Downstreams)
	}

	// Agent auto zone needs to be signed
	zd.Options[tdns.OptOnlineSigning] = true
	if tmp, exists := conf.Config.Internal.DnssecPolicies["default"]; !exists {
		return nil, fmt.Errorf("SetupAgentAutoZone: DnssecPolicy 'default' not defined")
	} else {
		zd.DnssecPolicy = &tmp
	}

	_, err = zd.SignZone(conf.Config.Internal.KeyDB, true)
	if err != nil {
		return nil, fmt.Errorf("SetupAgentAutoZone: failed to sign zone: %v", err)
	}

	err = zd.SetupZoneSigning(conf.Config.Internal.ResignQ)
	if err != nil {
		return nil, fmt.Errorf("SetupAgentAutoZone: failed to set up zone signing: %v", err)
	}

	return zd, nil
}

// publishApiTransport publishes HTTPS transport records (URI, address, TLSA, SVCB)
// for the agent identity zone. Called directly for auto zones or via OnFirstLoad for config zones.
func (conf *Config) publishApiTransport(zd *tdns.ZoneData) error {
	identity := conf.Config.MultiProvider.Identity
	lgAgent.Info("publishing URI record for API transport", "agent", identity)

	// Publish _https._tcp URI record
	uristr := strings.Replace(conf.Config.MultiProvider.Api.BaseUrl, "{TARGET}", identity, 1)
	uristr = strings.Replace(uristr, "{PORT}", fmt.Sprintf("%d", conf.Config.MultiProvider.Api.Port), 1)
	uri, err := url.Parse(uristr)
	if err != nil {
		return fmt.Errorf("publishApiTransport: failed to parse base URL: %q", uristr)
	}
	host, _, err := net.SplitHostPort(uri.Host)
	if err != nil {
		host = uri.Host
	}
	lgAgent.Debug("publishing _https._tcp URI record", "agent", identity, "target", host)

	err = zd.PublishUriRR("_https._tcp."+identity, identity, conf.Config.MultiProvider.Api.BaseUrl, conf.Config.MultiProvider.Api.Port)
	if err != nil {
		return fmt.Errorf("publishApiTransport: failed to publish URI record: %v", err)
	}
	lgAgent.Debug("published URI record", "agent", identity)

	for _, addr := range conf.Config.MultiProvider.Api.Addresses.Publish {
		err = zd.PublishAddrRR(host, addr)
		if err != nil {
			return fmt.Errorf("publishApiTransport: failed to publish address record for %s %s: %v", host, addr, err)
		}
	}
	lgAgent.Debug("published address records", "agent", identity)

	err = zd.PublishTlsaRR(host, conf.Config.MultiProvider.Api.Port, conf.Config.MultiProvider.Api.CertData)
	if err != nil {
		return fmt.Errorf("publishApiTransport: failed to publish TLSA record: %v", err)
	}
	lgAgent.Debug("published TLSA record", "agent", identity)

	var value []dns.SVCBKeyValue
	var ipv4hint, ipv6hint []net.IP

	for _, addr := range conf.Config.MultiProvider.Api.Addresses.Publish {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			ipv4hint = append(ipv4hint, ip)
		} else {
			ipv6hint = append(ipv6hint, ip)
		}
	}

	if conf.Config.MultiProvider.Api.Port != 0 {
		value = append(value, &dns.SVCBPort{Port: conf.Config.MultiProvider.Api.Port})
	}
	if len(ipv4hint) > 0 {
		value = append(value, &dns.SVCBIPv4Hint{Hint: ipv4hint})
	}
	if len(ipv6hint) > 0 {
		value = append(value, &dns.SVCBIPv6Hint{Hint: ipv6hint})
	}

	err = zd.PublishSvcbRR(host, conf.Config.MultiProvider.Api.Port, value)
	if err != nil {
		return fmt.Errorf("publishApiTransport: failed to publish SVCB record: %v", err)
	}
	lgAgent.Debug("published SVCB record for API transport", "agent", identity)

	return nil
}

// publishDnsTransport publishes DNS transport records (URI, address, KEY, JWK, SVCB)
// for the agent identity zone. Called directly for auto zones or via OnFirstLoad for config zones.
func (conf *Config) publishDnsTransport(zd *tdns.ZoneData) error {
	identity := dns.Fqdn(conf.Config.MultiProvider.Identity)
	lgAgent.Info("publishing DNS transport records", "agent", identity)

	uristr := strings.Replace(conf.Config.MultiProvider.Dns.BaseUrl, "{TARGET}", identity, 1)
	uristr = strings.Replace(uristr, "{PORT}", fmt.Sprintf("%d", conf.Config.MultiProvider.Dns.Port), 1)
	uri, err := url.Parse(uristr)
	if err != nil {
		return fmt.Errorf("publishDnsTransport: failed to parse base URL: %q", uristr)
	}

	lgAgent.Debug("parsed DNS transport URI", "uri", uri, "host", uri.Host)
	host, _, err := net.SplitHostPort(uri.Host)
	if err != nil {
		host = uri.Host
	}
	lgAgent.Debug("publishing _dns._tcp URI record", "agent", identity, "target", host)

	err = zd.PublishUriRR("_dns._tcp."+identity, identity, conf.Config.MultiProvider.Dns.BaseUrl, conf.Config.MultiProvider.Dns.Port)
	if err != nil {
		return fmt.Errorf("publishDnsTransport: failed to publish URI record: %v", err)
	}
	lgAgent.Debug("published DNS URI record", "agent", identity)

	for _, addr := range conf.Config.MultiProvider.Dns.Addresses.Publish {
		err = zd.PublishAddrRR(host, addr)
		if err != nil {
			return fmt.Errorf("publishDnsTransport: failed to publish address record for %s %s: %v", host, addr, err)
		}
	}
	lgAgent.Debug("published address records", "agent", identity)

	err = AgentSig0KeyPrep(zd, host, NewHsyncDB(zd.KeyDB))
	if err != nil {
		return fmt.Errorf("publishDnsTransport: failed to publish KEY record: %v", err)
	}
	lgAgent.Debug("published KEY record", "agent", identity)

	publishName := "dns." + identity
	err = AgentJWKKeyPrep(zd, publishName, NewHsyncDB(zd.KeyDB), conf.Config.MultiProvider)
	if err != nil {
		lgAgent.Warn("failed to publish JWK record, continuing without JWK", "err", err)
	} else {
		lgAgent.Debug("published JWK record", "name", publishName)
	}

	var value []dns.SVCBKeyValue
	var ipv4hint, ipv6hint []net.IP

	for _, addr := range conf.Config.MultiProvider.Dns.Addresses.Publish {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			ipv4hint = append(ipv4hint, ip)
		} else {
			ipv6hint = append(ipv6hint, ip)
		}
	}

	if conf.Config.MultiProvider.Dns.Port != 0 {
		value = append(value, &dns.SVCBPort{Port: conf.Config.MultiProvider.Dns.Port})
	}
	if len(ipv4hint) > 0 {
		value = append(value, &dns.SVCBIPv4Hint{Hint: ipv4hint})
	}
	if len(ipv6hint) > 0 {
		value = append(value, &dns.SVCBIPv6Hint{Hint: ipv6hint})
	}

	err = zd.PublishSvcbRR(host, conf.Config.MultiProvider.Dns.Port, value)
	if err != nil {
		return fmt.Errorf("publishDnsTransport: failed to publish SVCB record: %v", err)
	}
	lgAgent.Debug("published SVCB record for DNS transport", "agent", identity)

	return nil
}

func (conf *Config) SetupAgent(all_zones []string) error {
	lgAgent.Debug("SetupAgent enter", "zones", all_zones)

	if len(conf.Config.MultiProvider.Api.Addresses.Listen) == 0 && len(conf.Config.MultiProvider.Dns.Addresses.Listen) == 0 {
		lgAgent.Error("neither API nor DNS addresses set in config file")
		return errors.New("SetupAgent: neither API nor DNS addresses set in config file")
	}

	// Ensure identity is FQDN
	conf.Config.MultiProvider.Identity = dns.Fqdn(conf.Config.MultiProvider.Identity)

	// Determine if agent identity zone is an auto zone or a config-defined zone
	isAutoZone := !slices.Contains(all_zones, conf.Config.MultiProvider.Identity)
	var autoZd *tdns.ZoneData

	// Create auto zone for agent identity if needed
	if isAutoZone {
		var err error
		autoZd, err = conf.SetupAgentAutoZone(conf.Config.MultiProvider.Identity)
		if err != nil {
			return fmt.Errorf("SetupAgent: failed to create auto zone for agent identity %q: %v",
				conf.Config.MultiProvider.Identity, err)
		}
	}

	// Determine which transports need setup
	apiSupported := slices.Contains(conf.Config.MultiProvider.SupportedMechanisms, "api")
	wantApi := apiSupported && len(conf.Config.MultiProvider.Api.Addresses.Publish) > 0
	dnsSupported := slices.Contains(conf.Config.MultiProvider.SupportedMechanisms, "dns")
	wantDns := dnsSupported && len(conf.Config.MultiProvider.Dns.Addresses.Publish) > 0

	// Load and verify API certificate if API transport is configured
	if wantApi {
		certFile := conf.Config.MultiProvider.Api.CertFile
		keyFile := conf.Config.MultiProvider.Api.KeyFile

		if certFile == "" || keyFile == "" {
			return errors.New("SetupAgent: API transport defined, but cert or key file not set")
		}

		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			return fmt.Errorf("SetupAgent: error reading cert file: %v", err)
		}

		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("SetupAgent: error reading key file: %v", err)
		}

		conf.Config.MultiProvider.Api.CertData = string(certPEM)
		conf.Config.MultiProvider.Api.KeyData = string(keyPEM)

		block, _ := pem.Decode(certPEM)
		if block == nil {
			return fmt.Errorf("SetupAgent: failed to parse certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("SetupAgent: failed to parse certificate: %v", err)
		}

		certCN := strings.TrimSuffix(cert.Subject.CommonName, ".")
		agentID := strings.TrimSuffix(conf.Config.MultiProvider.Identity, ".")
		if certCN != agentID {
			return fmt.Errorf("SetupAgent: certificate CN %q does not match agent identity %q",
				cert.Subject.CommonName, conf.Config.MultiProvider.Identity)
		}

		lgAgent.Info("client certificate loaded", "subject", cert.Subject.CommonName,
			"notBefore", cert.NotBefore, "notAfter", cert.NotAfter)
	}

	if isAutoZone {
		// Auto zone is already fully populated — publish transport records directly
		if wantApi {
			if err := conf.publishApiTransport(autoZd); err != nil {
				return fmt.Errorf("SetupAgent: failed to publish API transport: %v", err)
			}
		}
		if wantDns {
			if err := conf.publishDnsTransport(autoZd); err != nil {
				return fmt.Errorf("SetupAgent: failed to publish DNS transport: %v", err)
			}
		}
	} else {
		// Config-defined zone — register OnFirstLoad callbacks (zone not loaded yet)
		zdp, ok := tdns.Zones.Get(conf.Config.MultiProvider.Identity)
		if !ok {
			return fmt.Errorf("SetupAgent: config zone %q not found in Zones", conf.Config.MultiProvider.Identity)
		}
		if wantApi {
			zdp.OnFirstLoad = append(zdp.OnFirstLoad, func(zd *tdns.ZoneData) {
				if err := conf.publishApiTransport(zd); err != nil {
					lgAgent.Error("publishApiTransport failed in OnFirstLoad", "zone", zd.ZoneName, "err", err)
				}
			})
		}
		if wantDns {
			zdp.OnFirstLoad = append(zdp.OnFirstLoad, func(zd *tdns.ZoneData) {
				if err := conf.publishDnsTransport(zd); err != nil {
					lgAgent.Error("publishDnsTransport failed in OnFirstLoad", "zone", zd.ZoneName, "err", err)
				}
			})
		}
	}

	lgAgent.Debug("SetupAgent exit")
	return nil
}

func AgentSig0KeyPrep(zd *tdns.ZoneData, name string, hdb *HsyncDB) error {
	alg, err := parseKeygenAlgorithm("agent.update.keygen.algorithm", dns.ED25519)
	if err != nil {
		lgAgent.Error("parseKeygenAlgorithm failed", "zone", zd.ZoneName, "err", err)
		return err
	}

	return zd.Sig0KeyPreparation(name, alg, hdb.KeyDB)
}

// parseKeygenAlgorithm reads a DNS algorithm from a viper config key.
// Replicated from tdns (unexported).
func parseKeygenAlgorithm(configKey string, defaultAlg uint8) (uint8, error) {
	algstr := viper.GetString(configKey)
	alg := dns.StringToAlgorithm[strings.ToUpper(algstr)]
	if alg == 0 {
		lgAgent.Warn("unknown keygen algorithm, using default", "algorithm", algstr, "configKey", configKey, "default", dns.AlgorithmToString[defaultAlg])
		alg = defaultAlg
	}
	return alg, nil
}

// AgentJWKKeyPrep publishes a JWK record for the agent's JOSE/HPKE long-term public keys.
func AgentJWKKeyPrep(zd *tdns.ZoneData, publishname string, hdb *HsyncDB, mp *tdns.MultiProviderConf) error {
	lgAgent.Info("publishing JWK record", "zone", zd.ZoneName, "name", publishname)

	// Check if JWK publication is disabled
	if zd.Options[tdns.OptDontPublishJWK] {
		lgAgent.Debug("JWK publication disabled by dont-publish-jwk option", "zone", zd.ZoneName)
		return nil
	}

	// Load JOSE private key from config
	privKeyPath := strings.TrimSpace(mp.LongTermJosePrivKey)
	if privKeyPath == "" {
		return fmt.Errorf("AgentJWKKeyPrep: no JOSE key path configured")
	}

	privKeyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("AgentJWKKeyPrep: JOSE key file not found: %q", privKeyPath)
		}
		return fmt.Errorf("AgentJWKKeyPrep: failed to read JOSE key: %w", err)
	}

	// Strip comments from key file
	privKeyData = tdns.StripKeyFileComments(privKeyData)

	// Use JOSE backend to parse the key
	backend := jose.NewBackend()
	privKey, err := backend.ParsePrivateKey(privKeyData)
	if err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to parse JOSE private key: %w", err)
	}

	// Derive public key from private key
	joseBackend, ok := backend.(*jose.Backend)
	if !ok {
		return fmt.Errorf("AgentJWKKeyPrep: backend is not JOSE")
	}
	josePubKey, err := joseBackend.PublicFromPrivate(privKey)
	if err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to derive public key: %w", err)
	}

	// Serialize the JOSE public key to JWK JSON to extract the underlying key
	pubKeyData, err := backend.SerializePublicKey(josePubKey)
	if err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to serialize public key: %w", err)
	}

	// Parse the JWK JSON to extract the underlying ECDSA public key
	var jwk struct {
		Key *ecdsa.PublicKey `json:"-"`
		Kty string           `json:"kty"`
		Crv string           `json:"crv"`
		X   string           `json:"x"`
		Y   string           `json:"y"`
	}
	if err := json.Unmarshal(pubKeyData, &jwk); err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to parse JWK: %w", err)
	}

	// Manually decode the ECDSA coordinates from the JWK
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to decode X coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to decode Y coordinate: %w", err)
	}

	// Reconstruct the ECDSA public key with the correct curve
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return fmt.Errorf("AgentJWKKeyPrep: unsupported JWK curve %q", jwk.Crv)
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Check if HPKE key exists (future support)
	// TODO: Check for HPKE X25519 key when implemented
	hasHPKEKey := false
	use := ""
	if hasHPKEKey {
		use = "sig"
	}

	// Publish the JWK record at the publishname (dns.<identity>)
	err = zd.PublishJWKRR(publishname, ecdsaPubKey, use)
	if err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to publish JWK record: %w", err)
	}

	lgAgent.Info("published JWK record", "name", publishname)
	return nil
}

func (agent *Agent) NewAgentSyncApiClient(localagent *tdns.MultiProviderConf) error {
	if agent == nil {
		return fmt.Errorf("agent is nil")
	}

	// Check if API method is supported and TLSA record exists
	if agent.ApiDetails == nil {
		return fmt.Errorf("agent %s: ApiDetails not initialized", agent.Identity)
	}
	if !agent.ApiMethod || agent.ApiDetails.TlsaRR == nil {
		return fmt.Errorf("agent %s does not support the API Method", agent.Identity)
	}

	// Verify local agent has necessary certificates
	if localagent.Api.CertFile == "" || localagent.Api.KeyFile == "" {
		return fmt.Errorf("local agent config missing either cert or key file")
	}

	lgAgent.Debug("creating API client", "identity", agent.Identity, "baseurl", agent.ApiDetails.BaseUri)

	// Create API client
	api := AgentApi{
		ApiClient: tdns.NewClient(string(agent.Identity), agent.ApiDetails.BaseUri, "", "", "tlsa"),
	}

	// Load client certificate
	cert, err := tls.LoadX509KeyPair(localagent.Api.CertFile, localagent.Api.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load client certificate: %v", err)
	}

	// Configure TLS with client certificate
	tlsconfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// Configure certificate verification using TLSA record
	tlsconfig.InsecureSkipVerify = true
	tlsconfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %v", err)
			}

			if dns.Fqdn(cert.Subject.CommonName) != dns.Fqdn(string(agent.Identity)) {
				return fmt.Errorf("unexpected certificate common name %q (should have been %s)", cert.Subject.CommonName, agent.Identity)
			}

			err = tdns.VerifyCertAgainstTlsaRR(agent.ApiDetails.TlsaRR, rawCert)
			if err != nil {
				return fmt.Errorf("failed to verify certificate against TLSA record: %v", err)
			}

			lgAgent.Debug("verified cert against TLSA record", "agent", agent.Identity)
		}

		return nil
	}

	// Create HTTP client with TLS config
	api.ApiClient.Client = &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsconfig},
	}

	// Set debug flags
	api.ApiClient.Debug = tdns.Globals.Debug
	api.ApiClient.Verbose = tdns.Globals.Verbose

	// Configure API addresses if available
	if len(agent.ApiDetails.Addrs) > 0 {
		lgAgent.Debug("remote agent API addresses", "agent", agent.Identity, "addrs", agent.ApiDetails.Addrs)
		var addressesWithPort []string
		port := strconv.Itoa(int(agent.ApiDetails.Port))

		for _, addr := range agent.ApiDetails.Addrs {
			addressesWithPort = append(addressesWithPort, net.JoinHostPort(addr, port))
		}

		api.ApiClient.Addresses = addressesWithPort
	}

	lgAgent.Debug("setting up agent-to-agent sync API client",
		"agent", agent.Identity, "baseurl", api.ApiClient.BaseUrl, "authmethod", api.ApiClient.AuthMethod)

	// Assign the API client to the agent
	agent.Api = &api

	return nil
}
