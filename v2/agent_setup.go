/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"context"
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
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// SetupAgentAutoZone creates the agent's identity zone and returns it held:
// the transaction it returns keeps the zone unpublished (queries SERVFAIL,
// transfers refused) until SetupAgent has queued every transport record and
// commits it, so the zone's first serial is the complete identity and never
// SOA and NS alone (tdns #653). The signing pass below runs under that hold:
// it stages the keys and the signatures and installs nothing, and the commit's
// publish is the one that signs and installs the first snapshot.
//
// The zone is registered before this returns, so the options, notify targets
// and transfer ACL set here are set on a registered zone, as before.
func (conf *Config) SetupAgentAutoZone(ctx context.Context, zonename string) (*tdns.ZoneData, tdns.TxID, error) {
	lgAgent.Info("creating a minimal auto zone, held until its records are in", "zone", zonename)

	mp := conf.MpConfig()
	// The notified secondaries are granted transfer below, and the transfer
	// ACL takes addresses: refuse a notify target that is not an IP literal
	// before creating anything, rather than NOTIFY a secondary that will then
	// be denied the transfer.
	notify := tdns.NormalizeAddresses(mp.Local.Notify)
	for _, addr := range notify {
		if hostPrefix(addr) == "" {
			return nil, "", fmt.Errorf("SetupAgentAutoZone: multi-provider.local.notify entry %q is not an IP address[:port]; the identity zone's transfer ACL needs an address", addr)
		}
	}

	var zd *tdns.ZoneData
	var txid tdns.TxID
	var err error
	if len(mp.Local.Nameservers) > 0 {
		nsNames := make([]string, len(mp.Local.Nameservers))
		for i, ns := range mp.Local.Nameservers {
			nsNames[i] = dns.Fqdn(ns)
		}
		zd, txid, err = conf.Config.Internal.KeyDB.CreateAutoZoneHeld(zonename, nil, nsNames)
	} else {
		addrs, findErr := conf.Config.FindDnsEngineAddrs()
		if findErr != nil {
			return nil, "", fmt.Errorf("SetupAgentAutoZone: failed to find nameserver addresses: %v", findErr)
		}
		zd, txid, err = conf.Config.Internal.KeyDB.CreateAutoZoneHeld(zonename, addrs, nil)
	}
	if err != nil {
		return nil, "", fmt.Errorf("SetupAgentAutoZone: failed to create minimal auto zone for agent identity %q: %v", zonename, err)
	}
	zd.Options[tdns.OptAllowUpdates] = true
	// Wire SyncQ on the MPZoneData wrapper (SyncQ moved from tdns.ZoneData to MPZoneData)
	if mpzd, ok := Zones.Get(zonename); ok {
		mpzd.SyncQ = conf.InternalMp.SyncQ
	}

	// Check for local notify configuration and set downstream targets.
	// tdns keeps the NOTIFY targets in zd.Notify ([]PeerConf) and uses
	// zd.Downstreams as the provide-xfr ACL (empty => deny); before the
	// re-pin Downstreams WAS the notify list and transfers were not
	// ACL-gated per zone, so the notified secondaries are also granted
	// transfer access here to keep the auto zone transferable (every entry
	// is an IP literal, checked above).
	if len(notify) > 0 {
		for _, addr := range notify {
			zd.Notify = append(zd.Notify, tdns.PeerConf{Addr: addr, Key: tdns.NOKEY})
			zd.Downstreams = append(zd.Downstreams, tdns.AclEntry{Prefix: hostPrefix(addr), Key: tdns.NOKEY})
		}
		lgAgent.Debug("setting downstream notify targets", "zone", zonename, "notify", zd.Notify, "downstreams", zd.Downstreams)
	}

	// Agent auto zone needs to be signed
	zd.Options[tdns.OptOnlineSigning] = true
	if tmp, exists := conf.Config.Internal.DnssecPolicies["default"]; !exists {
		return nil, "", fmt.Errorf("SetupAgentAutoZone: DnssecPolicy 'default' not defined")
	} else {
		zd.DnssecPolicy = &tmp
	}

	// Under the hold: keys and signatures are staged, nothing is installed.
	_, err = zd.SignZone(ctx, conf.Config.Internal.KeyDB, true)
	if err != nil {
		return nil, "", fmt.Errorf("SetupAgentAutoZone: failed to sign zone: %v", err)
	}

	// With a parentsync: block configured the identity zone is a child of
	// its parent like any other zone this daemon is primary for: it
	// publishes CDS from its keys and hands its DS to the parent through the
	// schemes the parent advertises (DSYNC). Without one it stays an island
	// whose TLSA no validating resolver will trust. Finding the parent and its
	// DSYNC records takes the resolver: with imrengine off the sync could never
	// start, so the zone stays an island and the log says why.
	//
	// The option is set here; the work starts after the commit
	// (startIdentityParentSync): the CDS is synthesised from the published
	// apex and the SIG(0) key preparation reads it too, and a held zone has
	// no snapshot to read.
	if conf.identityZoneParentSync() {
		zd.Options[tdns.OptParentSync] = true
	} else if len(conf.Config.ParentSync.Schemes) > 0 {
		lgAgent.Warn("identity zone: parentsync is configured but imrengine is not active; the zone's delegation will not be synced", "zone", zonename)
	}

	// Renewal. tdns registers a zone for periodic re-signing when its config
	// carries a signing option; this zone has none (it is built here), so it
	// is put on the resigner's watchlist explicitly. The engine that reads
	// this queue is started in StartMPAgent; without it the zone was signed
	// once and never renewed.
	if q := conf.Config.Internal.ResignQ; q != nil {
		select {
		case q <- tdns.ResignRequest{Zd: zd, Reason: tdns.ResignPeriodic}:
		case <-time.After(5 * time.Second):
			return nil, "", fmt.Errorf("SetupAgentAutoZone: timeout registering zone %q for periodic re-signing", zd.ZoneName)
		}
	}

	return zd, txid, nil
}

// identityCommitTimeout bounds the wait for the commit's answer. The commit
// travels the update queue behind the identity's records and publishes in the
// updater's goroutine, so the answer follows within the time those take; tdns
// releases or fails a hold that outlives its own limit of the same length.
const identityCommitTimeout = 30 * time.Second

// commitIdentityZone commits the identity zone's creation transaction the way
// its records travelled: through the update queue, behind them, with a Resp.
// The zone is not Ready, so the commit's publish happens in the updater's
// goroutine and the answer says whether the first snapshot is installed. On
// success the gate the first hello waits on opens.
func (conf *Config) commitIdentityZone(ctx context.Context, zd *tdns.ZoneData, txid tdns.TxID) error {
	q := conf.Config.Internal.KeyDB.UpdateQ
	if q == nil {
		return fmt.Errorf("commitIdentityZone: KeyDB.UpdateQ is nil")
	}
	resp := make(chan tdns.ZoneUpdateResult, 1)
	// The send waits for the queue: a commit that gave up would leave the zone
	// held and failing closed.
	select {
	case q <- tdns.UpdateRequest{Cmd: tdns.UpdateCmdTxCommit, ZoneName: zd.ZoneName, TxID: txid, Resp: resp}:
	case <-ctx.Done():
		return fmt.Errorf("commitIdentityZone: %w before the commit of %s was queued", ctx.Err(), zd.ZoneName)
	}
	select {
	case res := <-resp:
		if res.Err != nil {
			return fmt.Errorf("identity zone %s was not published: %w", zd.ZoneName, res.Err)
		}
	case <-time.After(identityCommitTimeout):
		return fmt.Errorf("identity zone %s: no answer to its commit within %v", zd.ZoneName, identityCommitTimeout)
	case <-ctx.Done():
		return fmt.Errorf("commitIdentityZone: %w while waiting for the commit of %s", ctx.Err(), zd.ZoneName)
	}
	zd.Lock()
	serial := zd.CurrentSerial
	zd.Unlock()
	lgAgent.Info("identity zone published as one serial", "zone", zd.ZoneName, "serial", serial)
	conf.InternalMp.IdentityReady.Publish()
	return nil
}

// startIdentityParentSync publishes the identity zone's CDS and starts its
// delegation sync, once the zone is published: both read the zone's apex
// through accessors that need it Ready, which a held zone is not. The CDS is
// a serial of its own, after the one that carries the identity; the parent,
// not discovery, is what reads it.
//
// The delegation sync starts only once the zone serves the CDS. Its first
// step, the SIG(0) key preparation, writes the key store, and the updater
// persists the CDS update there too; the key store takes one transaction at
// a time and refuses a second rather than wait for it. With the CDS queued
// and not waited for, the two ran together and one of them lost: either the
// update was refused and the zone published no CDS, or no key was generated
// and the setup was queued without one.
func (conf *Config) startIdentityParentSync(ctx context.Context, zd *tdns.ZoneData) {
	if !zd.Options[tdns.OptParentSync] {
		return
	}
	if err := publishIdentityCds(ctx, zd); err != nil {
		lgAgent.Warn("identity zone: could not publish CDS", "zone", zd.ZoneName, "err", err)
	}
	go conf.syncIdentityDelegation(ctx, zd)
}

// publishIdentityCds publishes the CDS for the SEP keys of the zone's served
// DNSKEY RRset, as PublishCdsRRs does, and returns once the zone serves it.
func publishIdentityCds(ctx context.Context, zd *tdns.ZoneData) error {
	cds, err := zd.SynthesizeCdsRRs()
	if err != nil {
		return err
	}
	if len(cds) == 0 {
		return nil
	}
	return zd.PublishCDSAndWait(ctx, zd.KeyDB, cds)
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

func (conf *Config) SetupAgent(ctx context.Context, all_zones []string) error {
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
	var autoTx tdns.TxID

	// Create auto zone for agent identity if needed. It comes back held, and
	// is committed below once the transport records are queued. An error exit
	// between the two ends the daemon's start, so no held zone outlives it.
	if isAutoZone {
		var err error
		autoZd, autoTx, err = conf.SetupAgentAutoZone(ctx, mp.Identity)
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
		// The records are queued on the held zone, and the commit follows them
		// through the same queue: the first snapshot has them all, and the
		// first hello leaves only once it is installed.
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
		if err := conf.commitIdentityZone(ctx, autoZd, autoTx); err != nil {
			return fmt.Errorf("SetupAgent: %v", err)
		}
		conf.startIdentityParentSync(ctx, autoZd)
	} else {
		// A config-defined identity zone publishes its transport records when
		// it loads, one at a time, as before (step 2 is the auto zone). The
		// hello gate opens from the last of its first-load callbacks, below:
		// after the zone is served and its records are queued, which is the
		// best this path knows; whether they are published yet it cannot tell.
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
		zdp.OnFirstLoad = append(zdp.OnFirstLoad, func(zd *tdns.ZoneData) {
			lgAgent.Info("identity zone loaded and its transport records queued; the first hello may leave", "zone", zd.ZoneName)
			conf.InternalMp.IdentityReady.Publish()
		})
	}

	lgAgent.Debug("SetupAgent exit")
	return nil
}

// AgentSig0KeyPrep makes sure an identity zone holds the SIG(0) key that the
// DSYNC UPDATE scheme signs with, and publishes its KEY. The key is named after
// the zone: SendDelegationUpdate and the parent-side bootstrap both look it up
// under the zone name. It is prepared only for a parentsync child that may use
// UPDATE; any other zone has no use for it. The algorithm is
// parentsync.update.keygen.algorithm, the one DelegationSyncSetup generates with.
func AgentSig0KeyPrep(zd *tdns.ZoneData, ps tdns.ParentSyncConf, hdb *HsyncDB) error {
	if !identityZoneUsesUpdate(zd, ps.Schemes) {
		return nil
	}
	alg := keygenAlgorithm(ps.Update.Keygen.Algorithm, dns.ED25519)
	if err := zd.Sig0KeyPreparation(zd.ZoneName, alg, hdb.KeyDB); err != nil {
		return err
	}
	lgAgent.Debug("identity zone: SIG(0) key prepared", "zone", zd.ZoneName)
	return nil
}

// identityZoneUsesUpdate reports whether the zone is a parentsync child that
// may reach its parent through the UPDATE scheme, and so needs its SIG(0) key.
func identityZoneUsesUpdate(zd *tdns.ZoneData, schemes []string) bool {
	return zd.Options[tdns.OptParentSync] && slices.ContainsFunc(schemes, func(s string) bool {
		return strings.EqualFold(s, "update")
	})
}

// keygenAlgorithm maps a configured algorithm name to its number. An empty name
// means the default; an unknown one is reported and replaced by it.
func keygenAlgorithm(name string, defaultAlg uint8) uint8 {
	if name == "" {
		return defaultAlg
	}
	if alg := dns.StringToAlgorithm[strings.ToUpper(name)]; alg != 0 {
		return alg
	}
	lgAgent.Warn("unknown keygen algorithm, using default", "algorithm", name, "default", dns.AlgorithmToString[defaultAlg])
	return defaultAlg
}

// parentSyncKeygenAlgorithm is parentsync.update.keygen.algorithm for a SIG(0)
// keypair generated where no ParentSyncConf is in hand: leader election, when
// no peer has the zone's key. It reads the installed parentsync: block, which
// tdns folds a deprecated delegationsync.child: into and swaps in on reload.
// The viper key it replaces, delegationsync.child.update.keygen.algorithm,
// found the deprecated spelling only.
func parentSyncKeygenAlgorithm() uint8 {
	return keygenAlgorithm(tdns.ParentSyncConfig().Update.Keygen.Algorithm, dns.ED25519)
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

	// The configured backend parses the key
	backend, err := cryptoBackend(mp)
	if err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: %w", err)
	}
	privKey, err := backend.ParsePrivateKey(privKeyData)
	if err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to parse private key: %w", err)
	}

	// Derive public key from private key
	josePubKey, err := backend.PublicFromPrivate(privKey)
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

// hostPrefix turns a notify address (host or host:port) into the single-host
// CIDR that AclEntry.Prefix requires (ValidateACL rejects a bare IP).
// Returns "" when the host is not an IP literal.
func hostPrefix(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	if ip.Is4() {
		return ip.String() + "/32"
	}
	return ip.String() + "/128"
}

// identityZoneParentSync reports whether the identity zone acts as a
// parentsync child: a parentsync: block names at least one scheme, and the
// resolver that finds the parent and its DSYNC records is running.
// syncIdentityDelegation waits for that resolver, so starting it without one
// would wait for a readiness that is never published.
func (conf *Config) identityZoneParentSync() bool {
	imrActive := conf.Config.Imr.Active == nil || *conf.Config.Imr.Active
	return len(conf.Config.ParentSync.Schemes) > 0 && imrActive
}

// syncIdentityDelegation brings the parent's DS for the identity zone in
// line with the zone's keys through the schemes the parent advertises. It
// waits for the resolver the syncher discovers the parent's DSYNC records
// with, prepares the zone's SIG(0) key, then asks for an explicit sync and
// repeats until the parent agrees or the attempts run out: right after a
// cold start the parent may not yet see the zone at its nameservers and
// refuses a DS it cannot check. After the last attempt it gives up. tdns's
// zone updater re-queues a sync only after an update from outside the
// daemon, not after the daemon's own key changes, so the delegation then
// stays as it is until the next start. The parent is not set here: tdns
// resolves it through the resolver as for any other zone
// (AnalyseZoneDelegation, via ResolveParentVia), because the name one label
// up need not be a zone cut and a parent set on the zone is used as the
// UPDATE zone as it stands.
func (conf *Config) syncIdentityDelegation(ctx context.Context, zd *tdns.ZoneData) {
	if !conf.Config.Internal.ImrReady.Wait(ctx) {
		return
	}
	// The zone's SIG(0) key is prepared here, before the setup is queued. The
	// syncher is already running when the identity zone is set up, so a key
	// prepared elsewhere while a queued setup runs could leave both generating
	// one. In this order the setup finds the key and only bootstraps it.
	if err := AgentSig0KeyPrep(zd, conf.Config.ParentSync, NewHsyncDB(zd.KeyDB)); err != nil {
		lgAgent.Warn("identity zone: could not prepare the SIG(0) key; the delegation sync setup tries again", "zone", zd.ZoneName, "err", err)
	}
	// The UPDATE scheme signs with the zone's own SIG(0) key, and a parent
	// accepts that key only after the bootstrap in DelegationSyncSetup. tdns
	// queues that setup for the zones it loads (SetupZoneSync), but not for an
	// identity zone: it is not multi-provider, and this daemon builds it
	// itself. So it is queued here, ahead of the first sync; the syncher
	// handles requests in order.
	if identityZoneUsesUpdate(zd, conf.Config.ParentSync.Schemes) {
		select {
		case conf.Config.Internal.DelegationSyncQ <- tdns.DelegationSyncRequest{
			Command: "DELEGATION-SYNC-SETUP", ZoneName: zd.ZoneName, ZoneData: zd}:
		case <-ctx.Done():
			return
		}
	}
	const attempts = 12
	const interval = 15 * time.Second
	for attempt := 1; attempt <= attempts; attempt++ {
		resp := make(chan tdns.DelegationSyncStatus, 1)
		select {
		case conf.Config.Internal.DelegationSyncQ <- tdns.DelegationSyncRequest{
			Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: zd.ZoneName, ZoneData: zd, Response: resp}:
		case <-ctx.Done():
			return
		}
		var st tdns.DelegationSyncStatus
		select {
		case st = <-resp:
		case <-time.After(time.Minute):
			lgAgent.Warn("identity zone: no answer to the delegation sync request", "zone", zd.ZoneName, "attempt", attempt)
		case <-ctx.Done():
			return
		}
		switch {
		case st.InSync:
			lgAgent.Info("identity zone: delegation in sync with the parent", "zone", zd.ZoneName, "parent", zd.GetParent(), "attempt", attempt)
			return
		case !st.Error && st.Rcode == dns.RcodeSuccess && st.Msg != "":
			// Sent and accepted; the next round's analysis confirms it.
			lgAgent.Info("identity zone: delegation sent to the parent", "zone", zd.ZoneName, "parent", zd.GetParent(), "attempt", attempt, "msg", st.Msg)
		default:
			lgAgent.Warn("identity zone: delegation sync not accepted yet", "zone", zd.ZoneName, "parent", zd.GetParent(),
				"attempt", attempt, "rcode", dns.RcodeToString[int(st.Rcode)], "err", st.ErrorMsg, "msg", st.Msg)
		}
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return
		}
	}
	lgAgent.Error("identity zone: delegation sync gave up", "zone", zd.ZoneName, "parent", zd.GetParent(), "attempts", attempts)
}
