#!/usr/bin/env python3
"""
Generate every config and zone of the mp-policy-matrix rig from cells.tsv.

Called by setup.sh; not meant to be run by hand. Everything the rig needs is
derived from the cell table and the port plan below, so that adding a cell
is one line in cells.tsv and the transfer topology (which signer a
non-signing provider pulls from) can never disagree with the HSYNC3 upstream
the zone declares -- both come from the same row.

Usage: gen.py RIG CELLS_TSV OUTDIR [cell ...]
  RIG       absolute work root the configs will name (/var/tmp/mp-policy-matrix)
  OUTDIR    where to write (setup.sh passes RIG itself)
  cell ...  optional subset of zone names; default all rows

Placeholders left for setup.sh: @APIKEY_<name>@ (one per daemon, minted at
seed time). Key and certificate paths are absolute under RIG; setup.sh mints
the files.
"""
import os
import sys

RIG = sys.argv[1]
CELLS_TSV = sys.argv[2]
OUT = sys.argv[3]
ONLY = set(sys.argv[4:])

PARENT = "rig.test."
WORLD = "world." + PARENT
WORLD_DNS = 5300
WORLD_API = 5301
AUDITOR_ID = "auditor." + PARENT
AUD = {"dns": 8456, "api": 7456, "imr": 5456, "syncapi": 9456}
PROVIDERS = ["p1", "p2", "p3"]


def ports(p):
    n = int(p[1])
    return {
        "combiner_dns": 8000 + n * 100 + 55, "combiner_api": 7000 + n * 100 + 55,
        "signer_dns": 8000 + n * 100 + 53, "signer_api": 7000 + n * 100 + 53,
        "agent_dns": 8000 + n * 100 + 54, "agent_api": 7000 + n * 100 + 54,
        "agent_imr": 5000 + n * 100 + 54,
        "agent_syncapi": 9000 + n * 100 + 54,
    }


def ident(kind, p):
    return f"{kind}.{p}.{PARENT}"


def ns_name(p, i=1):
    return f"ns{i}.{p}.{PARENT}"


# ---------------------------------------------------------------- cells
cells = []
for line in open(CELLS_TSV):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    zone, P, S, nsmgmt, providers, signers, upstreams = line.split("\t")
    if ONLY and zone not in ONLY:
        continue
    providers = providers.split(",")
    signers = [] if signers == "-" else signers.split(",")
    ups = {}
    if upstreams != "-":
        for pair in upstreams.split(","):
            d, u = pair.split(":")
            ups[d] = u
    for p in providers:
        if p not in signers and p not in ups:
            raise SystemExit(f"{zone}: non-signer {p} has no upstream")
    cells.append(dict(zone=zone, P=int(P), S=int(S), nsmgmt=nsmgmt,
                      providers=providers, signers=signers, upstreams=ups))
if not cells:
    raise SystemExit("no cells selected")

active_providers = sorted({p for c in cells for p in c["providers"]}, key=lambda p: PROVIDERS.index(p))


def w(path, text):
    full = os.path.join(OUT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        f.write(text)


# ---------------------------------------------------------------- zones
def cell_zone(c):
    z = c["zone"]
    lines = [f"$TTL 300",
             f"{z} 300 IN SOA {ns_name(c['providers'][0])} hostmaster.{z} 2026091101 30 15 604800 300",
             ""]
    for p in c["providers"]:
        lines.append(f"{z} 300 IN NS {ns_name(p)}")
    lines.append("")
    lines.append("; multi-provider coordination")
    for p in c["providers"]:
        up = c["upstreams"].get(p, ".")
        lines.append(f"{z} 300 IN HSYNC3 ON {p} {ident('agent', p)} {up}")
    lines.append(f"{z} 300 IN HSYNC3 ON aud {AUDITOR_ID} .")
    params = [f'servers="{",".join(c["providers"])}"']
    if c["signers"]:
        params.append(f'signers="{",".join(c["signers"])}"')
    params += [f'nsmgmt="{c["nsmgmt"]}"', 'parentsync="owner"', 'auditors="aud"']
    lines.append(f"{z} 300 IN HSYNCPARAM {' '.join(params)}")
    lines.append("")
    lines.append("; ordinary content, must pass through every provider unchanged")
    lines.append(f"www.{z} 300 IN A 192.0.2.10")
    lines.append(f"www.{z} 300 IN AAAA 2001:db8::10")
    lines.append(f"{z} 300 IN TXT \"cell {z} P={c['P']} S={c['S']} nsmgmt={c['nsmgmt']}\"")
    lines.append("")
    return "\n".join(lines)


def parent_zone():
    lines = ["$TTL 300",
             f"{PARENT} 300 IN SOA {WORLD} hostmaster.{PARENT} 2026091101 30 15 604800 300",
             f"{PARENT} 300 IN NS {WORLD}",
             f"{WORLD} 300 IN A 127.0.0.1",
             ""]
    lines.append("; provider nameserver names (the 'own suffix' of each provider)")
    for p in active_providers:
        for i in (1, 2, 3):
            lines.append(f"{ns_name(p, i)} 300 IN A 127.0.0.1")
    lines.append("")
    lines.append("; identity zones, served by the agents and slaved by the world server")
    for p in active_providers:
        lines.append(f"{ident('agent', p)} 300 IN NS {WORLD}")
    lines.append(f"{AUDITOR_ID} 300 IN NS {WORLD}")
    lines.append("")
    lines.append("; the customer zones")
    for c in cells:
        for p in c["providers"]:
            lines.append(f"{c['zone']} 300 IN NS {ns_name(p)}")
    lines.append("")
    return "\n".join(lines)


w(f"zones/{PARENT}zone", parent_zone())
for c in cells:
    w(f"zones/{c['zone']}zone", cell_zone(c))

# ---------------------------------------------------------------- world
def world_conf():
    combiners = [f"127.0.0.1:{ports(p)['combiner_dns']}" for p in active_providers]
    aud = f"127.0.0.1:{AUD['dns']}"
    out = f"""# The zone owner's server for every cell, and the stand-in for the public
# DNS: primary for {PARENT}, secondary for the agents' identity zones.
# Generated by gen.py from cells.tsv -- do not edit.
service:
   name:       TDNS-AUTH
   identities: [ {WORLD} ]
   verbose:    true
   debug:      false
   refresh:    true
   maxrefresh: 30

dnsengine:
   addresses:  [ 127.0.0.1:{WORLD_DNS} ]
   transports: [ do53 ]

apiserver:
   addresses:  [ 127.0.0.1:{WORLD_API} ]
   apikey:     @APIKEY_world@
   certfile:   {RIG}/world/certs/world.crt
   keyfile:    {RIG}/world/certs/world.key

imrengine:
   active:     false

db:
   file:  {RIG}/world/tdns-auth.db

log:
   file:   {RIG}/world/tdns-auth.log
   level:  info

templates:
   - name:      owner
     type:      primary
     store:     map
     notify:    [ {', '.join(combiners + [aud])} ]

   - name:      identity
     type:      secondary
     store:     map

zones:
   - name:      {PARENT}
     template:  owner
     zonefile:  {RIG}/zones/{PARENT}zone
"""
    for c in cells:
        out += f"""
   - name:      {c['zone']}
     template:  owner
     zonefile:  {RIG}/zones/{c['zone']}zone
"""
    for p in active_providers:
        out += f"""
   - name:      {ident('agent', p)}
     template:  identity
     primary:   127.0.0.1:{ports(p)['agent_dns']}
"""
    out += f"""
   - name:      {AUDITOR_ID}
     template:  identity
     primary:   127.0.0.1:{AUD['dns']}
"""
    return out


w("world/tdns-auth.yaml", world_conf())

# ---------------------------------------------------------------- shared blocks
STUBS = f"""   stubs:
      - zone:    {PARENT}
        servers:
           - name:  {WORLD}
             addrs: [ 127.0.0.1 ]
"""

INTERVALS = """   syncengine:
      intervals:
         beatinterval:        10
         helloretry:          5
         discoveryretry:      5
         hello_fast_attempts: 3
         hello_fast_interval: 2
"""

# The shape the pinned tdns parses: sigvalidity is a policy-level block
# (default/dnskey/ds). The per-key sigvalidity of older configs makes the
# whole policy "invalid, ignored", after which key generation fails with
# "unknown algorithm: 0".
#
# The daemon refuses a policy whose validity is not above
# 2 x (served TTL + propagation delay), and a policy below the floor makes
# it SERVFAIL the zone rather than serve it. The signer publishes DNSKEYs
# with a 1 h TTL and the agents' and auditor's auto-created identity zones
# carry a 1 h TTL (tdns CreateAutoZone; it was 24 h before the mp-pin
# branch's fix, which is why tdns-mp pins that branch), so 6 h clears
# every floor with margin and 2 h does not.
POLICY = """dnssecpolicies:
   default:
      algorithm:   ED25519
      sigvalidity:
         default:   6h
         dnskey:    12h
         ds:        12h
      ksk:
         lifetime:  forever
      zsk:
         lifetime:  forever
"""


def zones_for(p):
    return [c for c in cells if p in c["providers"]]


# ---------------------------------------------------------------- agent
def agent_conf(p):
    P = ports(p)
    d = f"{RIG}/{p}"
    out = f"""# Provider {p}: tdns-mpagent. Generated by gen.py -- do not edit.
multi-provider:
   role:           agent
   identity:       {ident('agent', p)}
   supported_mechanisms: [ dns ]
   long_term_jose_priv_key: {d}/keys/agent.jose.priv.json
   combiner:
      identity:                {ident('combiner', p)}
      address:                 127.0.0.1:{P['combiner_dns']}
      long_term_jose_pub_key:  {d}/keys/combiner.jose.pub.json
   signer:
      identity:                {ident('signer', p)}
      address:                 127.0.0.1:{P['signer_dns']}
      long_term_jose_pub_key:  {d}/keys/signer.jose.pub.json
   local:
      # NS of the auto-created identity zone; the world server slaves it
      nameservers:   [ {WORLD} ]
      notify:        [ 127.0.0.1:{WORLD_DNS} ]
   remote:
      LocateInterval: 30
   xfr:
      outgoing:
         addresses:  [ 127.0.0.1:{P['signer_dns']} ]
         auth:       []
      incoming:
         addresses:  [ 127.0.0.1:{P['signer_dns']} ]
         auth:       []
   # The API mechanism is not used (supported_mechanisms is dns only) and
   # nothing is published for it, but the daemon wants a listener.
   api:
      addresses:
         publish:    []
         listen:     [ 127.0.0.1:{P['agent_syncapi']} ]
      baseurl:       https://api.{{TARGET}}:{{PORT}}/api/v1
      port:          {P['agent_syncapi']}
      certfile:      {d}/certs/agent.crt
      keyfile:       {d}/certs/agent.key
   dns:
      addresses:
         publish:    [ 127.0.0.1 ]
         listen:     [ 127.0.0.1:{P['agent_dns']} ]
      baseurl:       dns://dns.{{TARGET}}:{{PORT}}/
      port:          {P['agent_dns']}
{INTERVALS}
service:
   name:           TDNS-MPAGENT
   verbose:        true
   debug:          false
   refresh:        true
   maxrefresh:     30

dnsengine:
   addresses:      [ 127.0.0.1:{P['agent_dns']} ]
   transports:     [ do53 ]

apiserver:
   addresses:      [ 127.0.0.1:{P['agent_api']} ]
   apikey:         @APIKEY_{p}_agent@
   certfile:       {d}/certs/agent.crt
   keyfile:        {d}/certs/agent.key

delegationsync:
   leader-election-ttl: 60m
   child:
      schemes:     [ notify, update ]
      update:
         keygen:
            mode:       internal
            algorithm:  ED25519

keybootstrap:
   consistent-lookup:
      iterations:  3
      interval:    60
      nameservers: all

imrengine:
   active:         true
   addresses:      [ 127.0.0.1:{P['agent_imr']} ]
   transports:     [ do53 ]
{STUBS}
{POLICY}
db:
   file:  {d}/agent.db

log:
   file:   {d}/agent.log
   level:  debug

templates:
   - name:           mpzone
     type:           secondary
     store:          map
     options:        [ multi-provider ]
     primary:        127.0.0.1:{P['signer_dns']}

zones:
"""
    for c in zones_for(p):
        out += f"   - name:      {c['zone']}\n     template:  mpzone\n\n"
    return out


# ---------------------------------------------------------------- combiner
def combiner_conf(p):
    P = ports(p)
    d = f"{RIG}/{p}"
    out = f"""# Provider {p}: tdns-mpcombiner. Generated by gen.py -- do not edit.
multi-provider:
   role:      combiner
   identity:  {ident('combiner', p)}
   long_term_jose_priv_key:  {d}/keys/combiner.jose.priv.json
   agents:
      - identity:               {ident('agent', p)}
        address:                127.0.0.1:{P['agent_dns']}
        long_term_jose_pub_key: {d}/keys/agent.jose.pub.json

service:
   name:           TDNS-MPCOMBINER
   verbose:        true
   debug:          false
   refresh:        true
   maxrefresh:     30

dnsengine:
   addresses:      [ 127.0.0.1:{P['combiner_dns']} ]
   transports:     [ do53 ]
   outbound_soa_serial: persist

apiserver:
   addresses:      [ 127.0.0.1:{P['combiner_api']} ]
   apikey:         @APIKEY_{p}_combiner@
   certfile:       {d}/certs/combiner.crt
   keyfile:        {d}/certs/combiner.key

db:
   file:  {d}/combiner.db

log:
   file:   {d}/combiner.log
   level:  debug

templates:
   - name:           mpzone
     type:           secondary
     store:          map
     options:        [ multi-provider ]
     primary:        127.0.0.1:{WORLD_DNS}
     notify:         [ 127.0.0.1:{P['signer_dns']} ]

zones:
"""
    for c in zones_for(p):
        out += f"   - name:      {c['zone']}\n     template:  mpzone\n\n"
    return out


# ---------------------------------------------------------------- signer
def signer_conf(p):
    P = ports(p)
    d = f"{RIG}/{p}"
    out = f"""# Provider {p}: tdns-mpsigner. Also this provider's public nameserver
# (port {P['signer_dns']}): what {p} serves is what answers here.
# Generated by gen.py -- do not edit.
#
# Zones are written out in full rather than through templates: in the
# pinned tdns a template's primary and notify lists override the zone's
# own, and both differ per zone here (a zone this provider signs is pulled
# from its combiner and NOTIFYs the agent and every downstream signer; a
# zone it is downstream in is pulled from the upstream provider's signer).
multi-provider:
   role:      signer
   active:    true
   identity:  {ident('signer', p)}
   long_term_jose_priv_key:  {d}/keys/signer.jose.priv.json
   agents:
      - identity:               {ident('agent', p)}
        address:                127.0.0.1:{P['agent_dns']}
        long_term_jose_pub_key: {d}/keys/agent.jose.pub.json

service:
   name:           TDNS-MPSIGNER
   verbose:        true
   debug:          false
   refresh:        true
   maxrefresh:     30
   resign:         true

dnsengine:
   addresses:      [ 127.0.0.1:{P['signer_dns']} ]
   transports:     [ do53 ]
   outbound_soa_serial: persist

apiserver:
   addresses:      [ 127.0.0.1:{P['signer_api']} ]
   apikey:         @APIKEY_{p}_signer@
   certfile:       {d}/certs/signer.crt
   keyfile:        {d}/certs/signer.key

resignerengine:
   interval:       60
   keygen:
      mode:        internal
      algorithm:   ED25519

kasp:
   propagation_delay:  60s
   check_interval:     10s
   standby_zsk_count:  1
   standby_ksk_count:  0

{POLICY}
db:
   file:  {d}/signer.db

log:
   file:   {d}/signer.log
   level:  debug

zones:
"""
    for c in zones_for(p):
        up = c["upstreams"].get(p)
        if up:
            out += (f"   # downstream of {up} in this cell: the signed zone comes from {up}'s signer\n"
                    f"   - name:          {c['zone']}\n"
                    f"     type:          secondary\n"
                    f"     store:         map\n"
                    f"     options:       [ multi-provider ]\n"
                    f"     primary:       127.0.0.1:{ports(up)['signer_dns']}\n"
                    f"     notify:        [ 127.0.0.1:{P['agent_dns']} ]\n\n")
        else:
            downstream = [q for q, u in c["upstreams"].items() if u == p]
            notify = [f"127.0.0.1:{P['agent_dns']}"] + [f"127.0.0.1:{ports(q)['signer_dns']}" for q in downstream]
            comment = f"   # {p} signs this cell" + (f"; {', '.join(downstream)} pull the signed zone from here" if downstream else "") + "\n"
            out += (comment +
                    f"   - name:          {c['zone']}\n"
                    f"     type:          secondary\n"
                    f"     store:         map\n"
                    f"     options:       [ multi-provider ]\n"
                    f"     primary:       127.0.0.1:{P['combiner_dns']}\n"
                    f"     dnssecpolicy:  default\n"
                    f"     notify:        [ {', '.join(notify)} ]\n\n")
    return out


for p in active_providers:
    w(f"{p}/tdns-mpagent.yaml", agent_conf(p))
    w(f"{p}/tdns-mpcombiner.yaml", combiner_conf(p))
    w(f"{p}/tdns-mpsigner.yaml", signer_conf(p))

# ---------------------------------------------------------------- auditor
def auditor_conf():
    d = f"{RIG}/auditor"
    out = f"""# The auditor: observer of every cell. Generated by gen.py -- do not edit.
multi-provider:
   role:           auditor
   identity:       {AUDITOR_ID}
   supported_mechanisms: [ dns ]
   long_term_jose_priv_key: {d}/keys/auditor.jose.priv.json
   local:
      nameservers:   [ {WORLD} ]
      notify:        [ 127.0.0.1:{WORLD_DNS} ]
   remote:
      LocateInterval: 30
   xfr:
      outgoing:
         addresses:  []
         auth:       []
      incoming:
         addresses:  []
         auth:       []
   api:
      addresses:
         publish:    []
         listen:     [ 127.0.0.1:{AUD['syncapi']} ]
      baseurl:       https://api.{{TARGET}}:{{PORT}}/api/v1
      port:          {AUD['syncapi']}
      certfile:      {d}/certs/auditor.crt
      keyfile:       {d}/certs/auditor.key
   dns:
      addresses:
         publish:    [ 127.0.0.1 ]
         listen:     [ 127.0.0.1:{AUD['dns']} ]
      baseurl:       dns://dns.{{TARGET}}:{{PORT}}/
      port:          {AUD['dns']}
{INTERVALS}
service:
   name:           TDNS-MPAUDITOR
   verbose:        true
   debug:          false
   refresh:        true
   maxrefresh:     30

dnsengine:
   addresses:      [ 127.0.0.1:{AUD['dns']} ]
   transports:     [ do53 ]

apiserver:
   addresses:      [ 127.0.0.1:{AUD['api']} ]
   apikey:         @APIKEY_auditor@
   certfile:       {d}/certs/auditor.crt
   keyfile:        {d}/certs/auditor.key

imrengine:
   active:         true
   addresses:      [ 127.0.0.1:{AUD['imr']} ]
   transports:     [ do53 ]
{STUBS}
{POLICY}
db:
   file:  {d}/auditor.db

log:
   file:   {d}/auditor.log
   level:  debug

audit:
   silence_threshold:   30s
   detector_interval:   10s
   web:
      enabled:          false

templates:
   - name:           mpzone
     type:           secondary
     store:           map
     options:        [ multi-provider ]
     primary:        127.0.0.1:{WORLD_DNS}

zones:
"""
    for c in cells:
        out += f"   - name:      {c['zone']}\n     template:  mpzone\n\n"
    return out


w("auditor/tdns-mpauditor.yaml", auditor_conf())

# ---------------------------------------------------------------- mpcli
def mpcli_conf():
    def entry(name, role, api, key, cfg, cmd, canonical=False):
        role_line = "" if canonical else f"     role:         {role}\n"
        return (f"   - name:         {name}\n{role_line}"
                f"     baseurl:      https://127.0.0.1:{api}/api/v1\n"
                f"     apikey:       @APIKEY_{key}@\n"
                f"     authmethod:   X-API-Key\n"
                f"     config_file:  {cfg}\n"
                f"     command:      {cmd}\n\n")
    out = ("# tdns-mpcli config for the rig: the built-in words address provider p1\n"
           "# and the auditor; every daemon is also an instance word (p1-agent ...\n"
           "# p3-signer, aud). Generated by gen.py -- do not edit.\n"
           "apiservers:\n")
    p = active_providers[0]
    P = ports(p)
    for kind, port in (("agent", P["agent_api"]), ("combiner", P["combiner_api"]), ("signer", P["signer_api"])):
        out += entry(f"tdns-mp{kind}", kind, port, f"{p}_{kind}", f"{RIG}/{p}/tdns-mp{kind}.yaml", f"{RIG}/bin/tdns-mp{kind}", canonical=True)
    out += entry("tdns-mpauditor", "auditor", AUD["api"], "auditor", f"{RIG}/auditor/tdns-mpauditor.yaml", f"{RIG}/bin/tdns-mpauditor", canonical=True)
    for p in active_providers:
        P = ports(p)
        for kind, port in (("agent", P["agent_api"]), ("combiner", P["combiner_api"]), ("signer", P["signer_api"])):
            out += entry(f"{p}-{kind}", kind, port, f"{p}_{kind}", f"{RIG}/{p}/tdns-mp{kind}.yaml", f"{RIG}/bin/tdns-mp{kind}")
    out += entry("aud", "auditor", AUD["api"], "auditor", f"{RIG}/auditor/tdns-mpauditor.yaml", f"{RIG}/bin/tdns-mpauditor")
    out += f"log:\n   file:   {RIG}/tdns-mpcli.log\n   level:  info\n"
    return out


w("tdns-mpcli.yaml", mpcli_conf())

# ---------------------------------------------------------------- the plan, for lib.sh
plan = ["# zone\tP\tS\tnsmgmt\tproviders\tsigners\tupstreams"]
for c in cells:
    ups = ",".join(f"{d}:{u}" for d, u in c["upstreams"].items()) or "-"
    plan.append("\t".join([c["zone"], str(c["P"]), str(c["S"]), c["nsmgmt"], ",".join(c["providers"]), ",".join(c["signers"]) or "-", ups]))
w("cells.tsv", "\n".join(plan) + "\n")
ports_out = [f"world_dns={WORLD_DNS}", f"world_api={WORLD_API}", f"auditor_dns={AUD['dns']}", f"auditor_api={AUD['api']}",
             f"providers=\"{' '.join(active_providers)}\""]
for p in active_providers:
    for k, v in ports(p).items():
        ports_out.append(f"{p}_{k}={v}")
w("ports.env", "\n".join(ports_out) + "\n")
print(f"generated: {len(cells)} cells, providers {' '.join(active_providers)}, auditor, world, mpcli")
