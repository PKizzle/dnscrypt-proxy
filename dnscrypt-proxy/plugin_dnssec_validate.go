package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/dnscrypt/dnscrypt-proxy/dnscrypt-proxy/dnssec"
	"github.com/jedisct1/dlog"
)

// dnssecInternalProto marks the queries the validator makes for itself.
//
// Building a chain means asking for keys, and those answers arrive through the
// same plugins as any other. Validating them would need their own chain, which
// would need its own keys: the plugin therefore stands aside for anything
// carrying this marker. It is a client protocol rather than a field on the
// state because that is what reaches the plugin from a query the proxy makes
// on its own behalf.
const dnssecInternalProto = "internal-dnssec"

type ValidationMode int

const (
	// ValidationOff does nothing.
	ValidationOff ValidationMode = iota
	// ValidationLog judges every answer and reports, but serves it either way.
	// The state to run in first: it says what enforcing would have refused,
	// against real traffic, before anything is refused.
	ValidationLog
	// ValidationEnforce refuses an answer whose signatures do not hold up.
	ValidationEnforce
)

func parseValidationMode(s string) (ValidationMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "disabled":
		return ValidationOff, nil
	case "log", "audit":
		return ValidationLog, nil
	case "enforce", "strict":
		return ValidationEnforce, nil
	}
	return ValidationOff, fmt.Errorf("unknown dnssec_validation mode [%s]: expected off, log or enforce", s)
}

// PluginDNSSECValidate checks an answer against the signatures the zone
// published, rather than trusting the resolver that relayed it.
//
// It runs on the response path and before the cache, so an answer is judged
// once, on the way in, rather than on every hit afterwards. Names the proxy
// answers for itself never reach it: a blocked name is synthesised on the query
// path, and refusing to serve a block because it carries no signature would be
// absurd.
type PluginDNSSECValidate struct {
	mode          ValidationMode
	insecureZones []string
	anchors       []*dns.DS
	fetcher       *dnssec.CachingFetcher
}

// dnssecVerdicts counts what validation concluded, so that the decision to move
// from logging refusals to making them can rest on how often a refusal would
// have happened rather than on how quiet the log looked.
var dnssecVerdicts struct {
	secure  atomic.Uint64
	bogus   atomic.Uint64
	unknown atomic.Uint64
}

func (plugin *PluginDNSSECValidate) Name() string {
	return "dnssec_validate"
}

func (plugin *PluginDNSSECValidate) Description() string {
	return "Verify answers against the signatures their zone published"
}

func (plugin *PluginDNSSECValidate) Init(proxy *Proxy) error {
	mode, err := parseValidationMode(proxy.dnssecValidationMode)
	if err != nil {
		return err
	}
	plugin.mode = mode
	plugin.anchors = dnssec.RootAnchors

	for _, zone := range proxy.dnssecInsecureZones {
		zone = strings.ToLower(strings.TrimSpace(zone))
		if zone == "" {
			continue
		}
		if !strings.HasSuffix(zone, ".") {
			zone += "."
		}
		plugin.insecureZones = append(plugin.insecureZones, zone)
	}

	plugin.fetcher = dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		return plugin.resolveInternally(proxy, qname, qtype)
	})

	switch plugin.mode {
	case ValidationLog:
		dlog.Notice("DNSSEC validation is reporting only; answers are served either way")
	case ValidationEnforce:
		dlog.Notice("DNSSEC validation is enforced; answers that fail are refused")
	}
	if len(plugin.insecureZones) > 0 {
		dlog.Noticef("DNSSEC validation is disabled for %v", plugin.insecureZones)
	}
	return nil
}

func (plugin *PluginDNSSECValidate) Drop() error { return nil }

func (plugin *PluginDNSSECValidate) Reload() error {
	plugin.fetcher.Forget()
	return nil
}

// resolveInternally asks the proxy for a record, through the same upstreams and
// the same encryption as any other query, marked so that this plugin leaves the
// answer alone.
func (plugin *PluginDNSSECValidate) resolveInternally(proxy *Proxy, qname string, qtype uint16) (*dns.Msg, error) {
	msg := dns.NewMsg(qname, qtype)
	if msg == nil {
		return nil, fmt.Errorf("cannot build a query for %s/%d", qname, qtype)
	}
	msg.RecursionDesired = true
	msg.Security = true // ask for the signatures; without DO there is nothing to check
	msg.UDPSize = uint16(MaxDNSPacketSize)

	if err := msg.Pack(); err != nil {
		return nil, err
	}
	response := proxy.processIncomingQuery(
		dnssecInternalProto, proxy.xTransport.mainProto, msg.Data, nil, nil, time.Now(), false,
	)
	if len(response) == 0 {
		return nil, fmt.Errorf("no response for %s/%d", qname, qtype)
	}
	decoded := &dns.Msg{Data: response}
	if err := decoded.Unpack(); err != nil {
		return nil, err
	}
	return decoded, nil
}

// isInsecureZone reports whether name is at or below a zone validation was
// switched off for.
func (plugin *PluginDNSSECValidate) isInsecureZone(name string) bool {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	for _, zone := range plugin.insecureZones {
		// The suffix has to fall on a label boundary. Matching the bare string
		// would exempt notbroken.test. along with broken.test. -- a different
		// zone, silently unprotected.
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return true
		}
	}
	return false
}

func (plugin *PluginDNSSECValidate) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if plugin.mode == ValidationOff {
		return nil
	}
	// The queries this plugin makes to do its job.
	if pluginsState.clientProto == dnssecInternalProto {
		return nil
	}
	// Answers the proxy produced itself were never signed by anyone and are not
	// upstream's to vouch for.
	if pluginsState.returnCode != PluginsReturnCodePass &&
		pluginsState.returnCode != PluginsReturnCodeNXDomain {
		return nil
	}
	if len(msg.Question) == 0 {
		return nil
	}
	qName := pluginsState.qName
	if qName == "" || plugin.isInsecureZone(qName) {
		return nil
	}

	result, why := plugin.judge(msg, qName)

	switch result {
	case dnssec.Secure:
		dnssecVerdicts.secure.Add(1)
	case dnssec.Bogus:
		dnssecVerdicts.bogus.Add(1)
	case dnssec.Indeterminate:
		dnssecVerdicts.unknown.Add(1)
		// Distinct from an unsigned zone, and worth saying so: the answer was
		// served unvalidated because something in the way of checking it did
		// not work -- a chain that could not be fetched, a key set that did not
		// arrive. An unsigned zone is a fact about the zone and stays quiet;
		// this is a fault on this side and would otherwise be invisible, since
		// both reach the client the same way.
		dlog.Debugf("DNSSEC could not check [%s]: %v", qName, why)
	default:
		dnssecVerdicts.unknown.Add(1)
		dlog.Debugf("DNSSEC did not vouch for [%s]: %v", qName, why)
	}

	if result != dnssec.Bogus {
		// Secure answers are marked as such; anything else is served without a
		// claim either way, which is what an unsigned zone deserves.
		msg.AuthenticatedData = result == dnssec.Secure
		return nil
	}

	if plugin.mode == ValidationLog {
		dlog.Warnf("DNSSEC would refuse [%s]: %v", qName, why)
		msg.AuthenticatedData = false
		return nil
	}
	dlog.Warnf("DNSSEC refused [%s]: %v", qName, why)
	pluginsState.action = PluginsActionReject
	pluginsState.returnCode = PluginsReturnCodeServFail
	return nil
}

// judge decides what an answer is worth.
func (plugin *PluginDNSSECValidate) judge(msg *dns.Msg, qName string) (dnssec.Result, error) {
	now := time.Now()
	records, _ := dnssec.SplitSignatures(msg.Answer)

	if len(records) == 0 {
		// Nothing was answered, so there is no signature to follow back to a
		// zone and the walk to the name is the only way to learn whether the
		// absence had to be proved.
		chain := dnssec.BuildChain(plugin.fetcher, qName, plugin.anchors, now)
		switch chain.Status {
		case dnssec.Secure:
		case dnssec.Insecure:
			// The zone is unsigned, so there is nothing to check. Whether the
			// delegation saying so was itself genuine is what the denial proofs
			// decide, and that is checked where the delegation is read.
			return dnssec.Insecure, nil
		default:
			// A chain that could not be built is not evidence that an answer is
			// forged. Refusing here would take the resolver down whenever the
			// path to the root is unreachable.
			return dnssec.Indeterminate, chain.Why
		}
		denial := dnssec.CollectDenial(msg.Ns)
		if denial.Empty() {
			return dnssec.Bogus, fmt.Errorf("a signed zone answered nothing and proved nothing")
		}
		qtype := dns.RRToType(msg.Question[0])
		if msg.Rcode == dns.RcodeNameError {
			if denial.ProvesNameError(qName, chain.Zone) {
				return dnssec.Secure, nil
			}
			return dnssec.Bogus, fmt.Errorf("no proof that %s does not exist", qName)
		}
		if denial.ProvesNoData(qName, qtype) {
			return dnssec.Secure, nil
		}
		return dnssec.Bogus, fmt.Errorf("no proof that %s holds no record of this type", qName)
	}

	// Each set is checked on its own, against a chain for the zone that signed
	// it. Deliberately not gated on a chain to the name that was asked: that
	// name is usually not a zone cut, so the walk to it stops at whatever the
	// parent is willing to say about a name it does not delegate -- which
	// decided nothing about the signatures actually on the answer, and threw
	// away perfectly good ones whenever the parent said little.
	//
	// An answer following a CNAME leaves the zone that was asked in any case:
	// the alias is signed by one zone and what it points at by another, and the
	// target's zone may not be signed at all.
	var chain dnssec.ChainResult
	worst := dnssec.Secure
	var worstErr error
	for _, set := range dnssec.GroupRRSets(msg.Answer) {
		res, err := plugin.judgeSet(set, chain, msg, now)
		switch res {
		case dnssec.Bogus:
			// A forged set is not redeemed by a genuine one beside it.
			return res, err
		case dnssec.Indeterminate:
			worst, worstErr = res, err
		case dnssec.Insecure:
			if worst != dnssec.Indeterminate {
				worst, worstErr = res, err
			}
		}
	}
	return worst, worstErr
}

// judgeSet checks one RRset against the zone that signed it.
//
// The signer is taken from the signature rather than found by probing for a
// delegation at each ancestor of the name. RFC 4035 section 5.3.1 names the
// RRSIG's signer field as the zone whose keys are to be used, subject to that
// zone actually containing the RRset -- without which any zone could offer to
// vouch for any name. Probing instead asks the parent about names that are not
// delegations at all, and depends on it returning a proof that says so; the
// signer field states the same thing directly and is signed.
func (plugin *PluginDNSSECValidate) judgeSet(set dnssec.RRSet, chain dnssec.ChainResult, msg *dns.Msg, now time.Time) (dnssec.Result, error) {
	if len(set.Sigs) == 0 {
		// Nothing claims to have signed this. Whether that is a forgery or an
		// ordinary unsigned answer depends on whether the zone holding the name
		// signs at all, which is what the walk to the name decides.
		owner := plugin.chainFor(set.Name, chain, now)
		switch owner.Status {
		case dnssec.Secure:
			return dnssec.Bogus, fmt.Errorf("%s is signed, but its %s record for %s is not",
				owner.Zone, dns.TypeToString[set.Type], set.Name)
		case dnssec.Insecure:
			return dnssec.Insecure, owner.Why
		default:
			return dnssec.Indeterminate, owner.Why
		}
	}

	var lastErr error
	for _, sig := range set.Sigs {
		// A signature naming a zone that does not contain the record it covers
		// is not evidence about that record, whoever signed it.
		if !dnssec.WithinZone(set.Name, sig.SignerName) {
			lastErr = fmt.Errorf("%s does not lie within %s, which signed for it", set.Name, sig.SignerName)
			continue
		}
		signer := plugin.chainFor(sig.SignerName, chain, now)
		switch signer.Status {
		case dnssec.Secure:
		case dnssec.Insecure:
			// The zone that signed is not itself vouched for by its parent, so
			// the signature proves nothing about authenticity.
			return dnssec.Insecure, signer.Why
		default:
			return dnssec.Indeterminate, signer.Why
		}
		res, verified, err := dnssec.VerifyRRSetDetail(set.Records, []*dns.RRSIG{sig}, signer.Keys, now)
		if res == dnssec.Secure {
			// RFC 4035 section 5.3.3: a signature made over a wildcard verifies
			// for every name beneath it, so it is evidence that the wildcard
			// exists rather than that it was the right answer here. The zone
			// has to have shown that nothing closer to the name does exist.
			if nextCloser, expanded := dnssec.WildcardNextCloser(verified, set.Name); expanded {
				if !dnssec.CollectDenial(msg.Ns).ProvesNoCloserMatch(nextCloser) {
					return dnssec.Bogus, fmt.Errorf(
						"%s was answered from a wildcard in %s with no proof that %s does not exist",
						set.Name, signer.Zone, nextCloser)
				}
			}
			return dnssec.Secure, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no signature over %s could be checked", set.Name)
	}
	return dnssec.Bogus, lastErr
}

// chainFor returns the chain to zone, reusing the one already built for the
// name that was asked when it is the same zone. The fetcher caches, so the
// difference is a map lookup rather than a query either way.
func (plugin *PluginDNSSECValidate) chainFor(zone string, chain dnssec.ChainResult, now time.Time) dnssec.ChainResult {
	if chain.Status == dnssec.Secure && dnssec.WithinZone(zone, chain.Zone) && dnssec.WithinZone(chain.Zone, zone) {
		return chain
	}
	return dnssec.BuildChain(plugin.fetcher, zone, plugin.anchors, now)
}

// PluginDNSSECRequest asks upstream for the signatures the validator needs.
//
// A client that does not set DO gets an answer with no signatures in it, and an
// answer with no signatures cannot be checked -- so the validator would report
// every signed zone as unsigned, which is exactly what it did before this
// existed. The bit is therefore set on the way out regardless of what the
// client asked for.
//
// What the client asked for is remembered, because it decides what comes back:
// a client that did not ask for DNSSEC records should not receive them, only
// the verdict, as the AD bit.
type PluginDNSSECRequest struct{}

func (plugin *PluginDNSSECRequest) Name() string { return "dnssec_request" }

func (plugin *PluginDNSSECRequest) Description() string {
	return "Request DNSSEC records so answers can be verified"
}

func (plugin *PluginDNSSECRequest) Init(_ *Proxy) error { return nil }
func (plugin *PluginDNSSECRequest) Drop() error         { return nil }
func (plugin *PluginDNSSECRequest) Reload() error       { return nil }

func (plugin *PluginDNSSECRequest) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if pluginsState.clientProto == dnssecInternalProto {
		// Already asks for signatures, and must not be recorded as a client
		// that wanted them.
		return nil
	}
	pluginsState.sessionData[dnssecClientWantedKey] = msg.Security
	pluginsState.sessionData[dnssecClientAskedADKey] = msg.AuthenticatedData
	msg.Security = true
	if msg.UDPSize == 0 || msg.UDPSize < 1232 {
		// Signatures do not fit in 512 bytes. Without room for them the answer
		// comes back truncated and there is nothing to verify.
		msg.UDPSize = 1232
	}
	return nil
}

// dnssecClientWantedKey records whether the client asked for DNSSEC records.
const dnssecClientWantedKey = "dnssec_client_wanted"

// dnssecClientAskedADKey records whether the client asked for the verdict alone.
const dnssecClientAskedADKey = "dnssec_client_asked_ad"

// stripDNSSECRecords removes the records only the validator needed, for a
// client that did not ask to see them.
func stripDNSSECRecords(msg *dns.Msg) {
	msg.Answer = withoutDNSSEC(msg.Answer)
	msg.Ns = withoutDNSSEC(msg.Ns)
	msg.Extra = withoutDNSSEC(msg.Extra)
}

func withoutDNSSEC(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return rrs
	}
	kept := rrs[:0]
	for _, rr := range rrs {
		switch dns.RRToType(rr) {
		case dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeDS:
			continue
		}
		kept = append(kept, rr)
	}
	return kept
}

// PluginDNSSECStrip returns an answer to the shape the client asked for.
//
// Registered after the cache deliberately. The validator sets the DO bit on
// every query so that there is something to check, and the records that come
// back are what the cache must keep: an entry stored without them cannot be
// checked when it is served again, and would be refused as unsigned by the very
// plugin that stripped it. So the cache stores what upstream sent, and the
// trimming happens here, on the way out, per client.
type PluginDNSSECStrip struct{}

func (plugin *PluginDNSSECStrip) Name() string { return "dnssec_strip" }

func (plugin *PluginDNSSECStrip) Description() string {
	return "Remove DNSSEC records from answers to clients that did not ask for them"
}

func (plugin *PluginDNSSECStrip) Init(_ *Proxy) error { return nil }
func (plugin *PluginDNSSECStrip) Drop() error         { return nil }
func (plugin *PluginDNSSECStrip) Reload() error       { return nil }

func (plugin *PluginDNSSECStrip) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if pluginsState.clientProto == dnssecInternalProto {
		// The validator's own fetches. These carry exactly the records it needs
		// to build a chain, and taking them out here leaves it unable to check
		// anything at all -- every answer insecure, for want of the keys.
		return nil
	}
	stripDNSSECForClient(pluginsState, msg)
	return nil
}

// stripDNSSECForClient trims an answer to what the client asked to see.
//
// The verdict still reaches a client that asked for none of this, as the AD
// bit -- but only if it asked in a way that gives the bit a meaning. RFC 6840
// section 5.8 reserves it for clients that set DO or AD; to anything else it is
// a bit that was not requested and cannot be acted on.
func stripDNSSECForClient(pluginsState *PluginsState, msg *dns.Msg) {
	wanted, _ := pluginsState.sessionData[dnssecClientWantedKey].(bool)
	askedForVerdict, _ := pluginsState.sessionData[dnssecClientAskedADKey].(bool)
	if !wanted {
		stripDNSSECRecords(msg)
	}
	if !wanted && !askedForVerdict {
		msg.AuthenticatedData = false
	}
}
