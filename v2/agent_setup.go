/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/johanix/tdns-transport/v2/crypto/jose"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (conf *Config) SetupAgentAutoZone(zonename string) (*tdns.ZoneData, error) {
	lgAgent.Info("creating a minimal auto zone", "zone", zonename)

	mp := conf.MpConfig()
	var zd *tdns.ZoneData
	var err error
	if len(mp.Local.Nameservers) > 0 {
		nsNames := make([]string, len(mp.Local.Nameservers))
		for i, ns := range mp.Local.Nameservers {
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
	// Wire SyncQ on the MPZoneData wrapper (SyncQ moved from tdns.ZoneData to MPZoneData)
	if mpzd, ok := Zones.Get(zonename); ok {
		mpzd.SyncQ = conf.InternalMp.SyncQ
	}

	// Check for local notify configuration and set downstream targets
	if len(mp.Local.Notify) > 0 {
		zd.Downstreams = tdns.NormalizeAddresses(mp.Local.Notify)
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
	mp := conf.MpConfig()
	identity := mp.Identity
	lgAgent.Info("publishing URI record for API transport", "agent", identity)

	// Publish _https._tcp URI record
	uristr := strings.Replace(mp.Api.BaseUrl, "{TARGET}", identity, 1)
	uristr = strings.Replace(uristr, "{PORT}", fmt.Sprintf("%d", mp.Api.Port), 1)
	uri, err := url.Parse(uristr)
	if err != nil {
		return fmt.Errorf("publishApiTransport: failed to parse base URL: %q", uristr)
	}
	host, _, err := net.SplitHostPort(uri.Host)
	if err != nil {
		host = uri.Host
	}
	lgAgent.Debug("publishing _https._tcp URI record", "agent", identity, "target", host)

	err = zd.PublishUriRR("_https._tcp."+identity, identity, mp.Api.BaseUrl, mp.Api.Port)
	if err != nil {
		return fmt.Errorf("publishApiTransport: failed to publish URI record: %v", err)
	}
	lgAgent.Debug("published URI record", "agent", identity)

	for _, addr := range mp.Api.Addresses.Publish {
		err = zd.PublishAddrRR(host, addr)
		if err != nil {
			return fmt.Errorf("publishApiTransport: failed to publish address record for %s %s: %v", host, addr, err)
		}
	}
	lgAgent.Debug("published address records", "agent", identity)

	err = zd.PublishTlsaRR(host, mp.Api.Port, mp.Api.CertData)
	if err != nil {
		return fmt.Errorf("publishApiTransport: failed to publish TLSA record: %v", err)
	}
	lgAgent.Debug("published TLSA record", "agent", identity)

	var value []dns.SVCBKeyValue
	var ipv4hint, ipv6hint []net.IP

	for _, addr := range mp.Api.Addresses.Publish {
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

	if mp.Api.Port != 0 {
		value = append(value, &dns.SVCBPort{Port: mp.Api.Port})
	}
	if len(ipv4hint) > 0 {
		value = append(value, &dns.SVCBIPv4Hint{Hint: ipv4hint})
	}
	if len(ipv6hint) > 0 {
		value = append(value, &dns.SVCBIPv6Hint{Hint: ipv6hint})
	}

	err = zd.PublishSvcbRR(host, mp.Api.Port, value)
	if err != nil {
		return fmt.Errorf("publishApiTransport: failed to publish SVCB record: %v", err)
	}
	lgAgent.Debug("published SVCB record for API transport", "agent", identity)

	return nil
}

// publishDnsTransport publishes DNS transport records (URI, address, KEY, JWK, SVCB)
// for the agent identity zone. Called directly for auto zones or via OnFirstLoad for config zones.
func (conf *Config) publishDnsTransport(zd *tdns.ZoneData) error {
	mp := conf.MpConfig()
	identity := dns.Fqdn(mp.Identity)
	lgAgent.Info("publishing DNS transport records", "agent", identity)

	uristr := strings.Replace(mp.Dns.BaseUrl, "{TARGET}", identity, 1)
	uristr = strings.Replace(uristr, "{PORT}", fmt.Sprintf("%d", mp.Dns.Port), 1)
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

	err = zd.PublishUriRR("_dns._tcp."+identity, identity, mp.Dns.BaseUrl, mp.Dns.Port)
	if err != nil {
		return fmt.Errorf("publishDnsTransport: failed to publish URI record: %v", err)
	}
	lgAgent.Debug("published DNS URI record", "agent", identity)

	for _, addr := range mp.Dns.Addresses.Publish {
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
	err = AgentJWKKeyPrep(zd, publishName, NewHsyncDB(zd.KeyDB), mp)
	if err != nil {
		lgAgent.Warn("failed to publish JWK record, continuing without JWK", "err", err)
	} else {
		lgAgent.Debug("published JWK record", "name", publishName)
	}

	var value []dns.SVCBKeyValue
	var ipv4hint, ipv6hint []net.IP

	for _, addr := range mp.Dns.Addresses.Publish {
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

	if mp.Dns.Port != 0 {
		value = append(value, &dns.SVCBPort{Port: mp.Dns.Port})
	}
	if len(ipv4hint) > 0 {
		value = append(value, &dns.SVCBIPv4Hint{Hint: ipv4hint})
	}
	if len(ipv6hint) > 0 {
		value = append(value, &dns.SVCBIPv6Hint{Hint: ipv6hint})
	}

	err = zd.PublishSvcbRR(host, mp.Dns.Port, value)
	if err != nil {
		return fmt.Errorf("publishDnsTransport: failed to publish SVCB record: %v", err)
	}
	lgAgent.Debug("published SVCB record for DNS transport", "agent", identity)

	return nil
}

func (conf *Config) SetupAgent(all_zones []string) error {
	lgAgent.Debug("SetupAgent enter", "zones", all_zones)

	mp := conf.MpConfig()
	if len(mp.Api.Addresses.Listen) == 0 && len(mp.Dns.Addresses.Listen) == 0 {
		lgAgent.Error("neither API nor DNS addresses set in config file")
		return errors.New("SetupAgent: neither API nor DNS addresses set in config file")
	}

	// Ensure identity is FQDN
	mp.Identity = dns.Fqdn(mp.Identity)

	// Determine if agent identity zone is an auto zone or a config-defined zone
	isAutoZone := !slices.Contains(all_zones, mp.Identity)
	var autoZd *tdns.ZoneData

	// Create auto zone for agent identity if needed
	if isAutoZone {
		var err error
		autoZd, err = conf.SetupAgentAutoZone(mp.Identity)
		if err != nil {
			return fmt.Errorf("SetupAgent: failed to create auto zone for agent identity %q: %v",
				mp.Identity, err)
		}
	}

	// Determine which transports need setup
	apiSupported := slices.Contains(mp.SupportedMechanisms, "api")
	wantApi := apiSupported && len(mp.Api.Addresses.Publish) > 0
	dnsSupported := slices.Contains(mp.SupportedMechanisms, "dns")
	wantDns := dnsSupported && len(mp.Dns.Addresses.Publish) > 0

	// Load and verify API certificate if API transport is configured
	if wantApi {
		certFile := mp.Api.CertFile
		keyFile := mp.Api.KeyFile

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

		mp.Api.CertData = string(certPEM)
		mp.Api.KeyData = string(keyPEM)

		block, _ := pem.Decode(certPEM)
		if block == nil {
			return fmt.Errorf("SetupAgent: failed to parse certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("SetupAgent: failed to parse certificate: %v", err)
		}

		certCN := strings.TrimSuffix(cert.Subject.CommonName, ".")
		agentID := strings.TrimSuffix(mp.Identity, ".")
		if certCN != agentID {
			return fmt.Errorf("SetupAgent: certificate CN %q does not match agent identity %q",
				cert.Subject.CommonName, mp.Identity)
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
		zdp, ok := Zones.Get(mp.Identity)
		if !ok {
			return fmt.Errorf("SetupAgent: config zone %q not found in Zones", mp.Identity)
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
func AgentJWKKeyPrep(zd *tdns.ZoneData, publishname string, hdb *HsyncDB, mp *MultiProviderConf) error {
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
