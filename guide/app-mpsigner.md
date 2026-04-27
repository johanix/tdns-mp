# tdns-mpsigner

**tdns-mpsigner** is the DNSSEC signer used in a
multi-provider deployment. It is a specialization of the
tdns authoritative server (**tdns-auth**) configured with
`multi-provider.role: signer`.

## Role in the Data Flow

```
Combiner --(AXFR/IXFR + NOTIFY)-->  Signer --(NOTIFY)--> Agent
                                       |
                                       v
                                   External resolvers
```

The signer:

1. Receives the combined (unsigned) zone via inbound zone
   transfer from the local **tdns-mpcombiner**.
2. Signs the zone with locally managed DNSSEC keys
   (online signing).
3. Serves the signed zone authoritatively to external
   resolvers.
4. Notifies the local **tdns-mpagent** that a new signed
   version is available.
5. Coordinates DNSKEY publication state with the agent via
   KEYSTATE EDNS(0) signaling, so that DNSKEY rollovers are
   consistent across all providers in the group.

## Design Constraints

1. The signer is the source of truth for local DNSKEYs. The
   agent does not derive DNSKEYs from zone transfer data;
   it learns them from the signer via KEYSTATE.

2. The signer is a regular tdns-auth instance with
   multi-provider role enabled. All standard tdns-auth
   features (online signing, dynamic zones, catalog zones,
   delegation-sync-parent for parent-zone roles) are
   available, subject to multi-provider policy.

3. Configuration uses the same YAML schema as tdns-auth,
   with an additional `multi-provider:` section. See the
   [Multi-Provider QuickStart](multi-provider-quickstart.md)
   section 4.3 for a working example.

## See Also

- [tdns-auth documentation](../../tdns/guide/app-tdns-auth.md)
  for the underlying authoritative server.
- [Multi-Provider Advanced Topics](multi-provider-advanced.md)
  for the KEYSTATE signaling protocol and DNSKEY
  publication flow.
