package main

import (
	"errors"
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

// A missing DNSSEC proof or an expired RRSIG can be stale recursive data rather
// than proof that the zone is broken. Try fresh encrypted upstreams before
// making a client wait for SERVFAIL. A signature mismatch still remains a
// cryptographic failure and is never promoted to a successful answer.
const dnssecResponseAttempts = 3

var errDNSSECIncompleteEvidence = errors.New("incomplete DNSSEC evidence")

type ValidationMode int

const (
	// ValidationOff does nothing.
	ValidationOff ValidationMode = iota
	// ValidationLog judges every answer and reports, but serves it either way.
	// The state to run in first: it says what enforcing would have refused,
	// against real traffic, before anything is refused.
	ValidationLog
	// ValidationEnforce returns SERVFAIL when validation fails or cannot finish.
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
	proxy         *Proxy
}

// dnssecVerdicts counts what validation concluded, so that the decision to move
// from logging refusals to making them can rest on how often a refusal would
// have happened rather than on how quiet the log looked.
// dnssecMode is what the validator does with a refusal, for anything reporting
// on it: "log" records what it would have refused and serves the answer anyway,
// which reads identically to "enforce" unless it is said out loud.
var dnssecMode atomic.Value

func init() { dnssecMode.Store("off") }

var dnssecVerdicts struct {
	secure atomic.Uint64
	bogus  atomic.Uint64
	// insecure is the ordinary case for most of the internet: a zone that signs
	// nothing. indeterminate is a fault on this side -- keys that did not
	// arrive, a chain that could not be walked. Counted apart because they mean
	// opposite things: one is the state of the world, the other is this
	// resolver failing to check and saying nothing about it.
	insecure      atomic.Uint64
	indeterminate atomic.Uint64
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
	plugin.proxy = proxy
	dnssecMode.Store(modeName(mode))
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
		dlog.Notice("DNSSEC validation is enforced; failed validation returns SERVFAIL")
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
	return plugin.resolveInternallyExcluding(proxy, qname, qtype, nil)
}

// resolveInternallyExcept obtains a fresh client-answer retry from a resolver
// other than excludeServerName. The normal chain fetcher calls
// resolveInternally, without an exclusion, because its lookups do not originate
// from the client-answer resolver.
func (plugin *PluginDNSSECValidate) resolveInternallyExcept(proxy *Proxy, qname string, qtype uint16, excludeServerName string) (*dns.Msg, error) {
	var excludedServerNames map[string]struct{}
	if excludeServerName != "" {
		excludedServerNames = map[string]struct{}{excludeServerName: {}}
	}
	return plugin.resolveInternallyExcluding(proxy, qname, qtype, excludedServerNames)
}

func (plugin *PluginDNSSECValidate) resolveInternallyExcluding(proxy *Proxy, qname string, qtype uint16, excludedServerNames map[string]struct{}) (*dns.Msg, error) {
	msg := dns.NewMsg(qname, qtype)
	if msg == nil {
		return nil, fmt.Errorf("cannot build a query for %s/%d", qname, qtype)
	}
	msg.RecursionDesired = true
	msg.Security = true // ask for the signatures; without DO there is nothing to check
	// RFC 6840 section 5.9 recommends CD on upstream validation queries so an
	// upstream validator returns the DNSSEC material we must verify ourselves.
	msg.CheckingDisabled = true
	msg.UDPSize = uint16(MaxDNSPacketSize)

	if err := msg.Pack(); err != nil {
		return nil, err
	}
	response := proxy.processIncomingQueryExcluding(
		dnssecInternalProto, proxy.xTransport.mainProto, msg.Data, nil, nil, time.Now(), false, excludedServerNames,
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
	if qName == "" {
		return nil
	}

	configuredInsecure := plugin.isInsecureZone(qName)
	var result dnssec.Result
	var why error
	if configuredInsecure {
		// A local policy exception says only that this validator deliberately
		// did not authenticate the name. It does not authorize an upstream's
		// AD assertion. Run it through the normal Insecure result path so AD is
		// cleared and monitoring accounts for the query instead of silently
		// omitting it from every DNSSEC total.
		result = dnssec.Insecure
		why = fmt.Errorf("%s matches a configured insecure zone", qName)
	} else {
		result, why = plugin.judge(msg, qName)
	}
	if plugin.proxy != nil && !configuredInsecure && retryableDNSSECFailure(result, why) {
		qtype := dns.RRToType(msg.Question[0])
		excludedServerNames := make(map[string]struct{}, dnssecResponseAttempts)
		if pluginsState.serverName != "" && pluginsState.serverName != "-" {
			excludedServerNames[pluginsState.serverName] = struct{}{}
		}
		for attempt := 1; attempt < dnssecResponseAttempts; attempt++ {
			retry, err := plugin.resolveInternallyExcluding(plugin.proxy, qName, qtype, excludedServerNames)
			if err != nil {
				continue
			}
			// The client transaction and question belong to the original query,
			// not to this private retry. Unpack into the existing message rather
			// than copying dns.Msg: its decoded form contains atomic state.
			originalID, originalQuestion := msg.ID, msg.Question
			msg.Data = retry.Data
			if err := msg.Unpack(); err != nil {
				continue
			}
			msg.ID = originalID
			msg.Question = originalQuestion
			result, why = plugin.judge(msg, qName)
			if !retryableDNSSECFailure(result, why) {
				break
			}
		}
	}

	pluginsState.sessionData[dnssecVerdictKey] = verdictName(result)
	if why != nil && result != dnssec.Secure {
		pluginsState.sessionData[dnssecReasonKey] = why.Error()
	}

	switch result {
	case dnssec.Secure:
		dnssecVerdicts.secure.Add(1)
	case dnssec.Bogus:
		dnssecVerdicts.bogus.Add(1)
	case dnssec.Indeterminate:
		dnssecVerdicts.indeterminate.Add(1)
		// Distinct from an unsigned zone, and worth saying so: the answer was
		// served unvalidated because something in the way of checking it did
		// not work -- a chain that could not be fetched, a key set that did not
		// arrive. An unsigned zone is a fact about the zone and stays quiet;
		// this is a fault on this side and would otherwise be invisible, since
		// both reach the client the same way.
		dlog.Debugf("DNSSEC could not check [%s]: %v", qName, why)
	default:
		dnssecVerdicts.insecure.Add(1)
		dlog.Debugf("DNSSEC did not vouch for [%s]: %v", qName, why)
	}

	if !plugin.mustReject(result, clientCheckingDisabled(pluginsState)) {
		// Secure answers are marked as such; anything else is served without a
		// claim either way. In log mode that also includes a result which
		// enforcement would have rejected; in enforce mode a CD client receives
		// the upstream response as RFC 4035 section 5.5 requires.
		msg.AuthenticatedData = result == dnssec.Secure
		if plugin.mode == ValidationLog && (result == dnssec.Bogus || result == dnssec.Indeterminate) {
			dlog.Warnf("DNSSEC would return SERVFAIL for [%s]: %v", qName, why)
		}
		return nil
	}

	dlog.Warnf("DNSSEC returned SERVFAIL for [%s]: %v", qName, why)
	edeCode := dnssecFailureEDE(result, why)
	failure := DNSSECFailureResponseFromMessage(pluginsState.questionMsg, edeCode)
	restoreDNSSECClientBits(pluginsState, failure)
	pluginsState.synthResponse = failure
	pluginsState.action = PluginsActionReject
	pluginsState.returnCode = PluginsReturnCodeServFail
	return nil
}

// retryableDNSSECFailure identifies failures for which a different recursive
// upstream can supply the missing evidence. A bad signature is evidence about
// the DNS data and must remain a failure; an unsupported NSEC3 cost is a local
// policy limit, not a transport condition another resolver can repair.
func retryableDNSSECFailure(result dnssec.Result, why error) bool {
	if result == dnssec.Indeterminate {
		return !errors.Is(why, dnssec.ErrUnsupportedNSEC3Iterations)
	}
	return result == dnssec.Bogus &&
		(errors.Is(why, errDNSSECIncompleteEvidence) ||
			errors.Is(why, dnssec.ErrSignatureOutsideValidity))
}

// dnssecFailureEDE preserves the reason a validator had to return SERVFAIL.
// RFC 9276 section 3.2 specifically asks for EDE 27 after an authenticated
// NSEC3 proof exceeds a resolver's iteration policy; describing that as
// generic DNSSEC Bogus wrongly blames the zone's signatures.
func dnssecFailureEDE(result dnssec.Result, why error) uint16 {
	if errors.Is(why, dnssec.ErrUnsupportedNSEC3Iterations) {
		return dns.ExtendedErrorUnsupportedNSEC3IterValue
	}
	if result == dnssec.Indeterminate {
		return dns.ExtendedErrorDNSSECIndeterminate
	}
	return dns.ExtendedErrorDNSBogus
}

// mustReject follows RFC 4035 section 5.5: when a validating server cannot
// validate an answer, it returns SERVFAIL unless the original query carried
// CD. "Indeterminate" is therefore useful in log mode but is not safe to
// serve as a validated answer in enforce mode.
func (plugin *PluginDNSSECValidate) mustReject(result dnssec.Result, checkingDisabled bool) bool {
	if plugin.mode != ValidationEnforce || checkingDisabled {
		return false
	}
	return result == dnssec.Bogus || result == dnssec.Indeterminate
}

// judge decides what an answer is worth.
func (plugin *PluginDNSSECValidate) judge(msg *dns.Msg, qName string) (dnssec.Result, error) {
	now := time.Now()
	records, _ := dnssec.SplitSignatures(msg.Answer)

	if len(records) == 0 {
		return plugin.judgeNegative(msg, qName, now)
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
	sets := dnssec.GroupRRSets(msg.Answer)
	dnames := make([]validatedDNAME, 0)

	// RFC 4035 section 3.2.3 permits an unsigned CNAME only when it is
	// demonstrably synthesized from an authenticated DNAME in this response.
	// Validate DNAME sets first so the CNAME exception cannot be used to slip a
	// forged alias past an otherwise secure zone.
	for _, set := range sets {
		if set.Type != dns.TypeDNAME {
			continue
		}
		res, err := plugin.judgeSet(set, chain, msg, now)
		switch res {
		case dnssec.Bogus:
			return res, err
		case dnssec.Indeterminate:
			worst, worstErr = res, err
		case dnssec.Insecure:
			if worst != dnssec.Indeterminate {
				worst, worstErr = res, err
			}
		}
		for _, rr := range set.Records {
			if dname, ok := rr.(*dns.DNAME); ok {
				dnames = append(dnames, validatedDNAME{record: dname, result: res, err: err})
			}
		}
	}

	for _, set := range sets {
		if set.Type == dns.TypeDNAME {
			continue
		}
		if res, err, synthesized := synthesizedCNAMEFromDNAME(set, dnames); synthesized {
			switch res {
			case dnssec.Bogus:
				return res, err
			case dnssec.Indeterminate:
				worst, worstErr = res, err
			case dnssec.Insecure:
				if worst != dnssec.Indeterminate {
					worst, worstErr = res, err
				}
			}
			continue
		}
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

	// A CNAME is not the requested data (except for QTYPE=CNAME itself). If
	// its target answered negatively, the authority proof is part of the
	// response that AD would vouch for and has to be checked too. Without this,
	// a signed alias plus an unsigned or forged target NODATA response is marked
	// secure merely because the alias happened to validate.
	if qtype := dns.RRToType(msg.Question[0]); qtype != dns.TypeCNAME && qtype != dns.TypeANY {
		res, err := plugin.judgeCNAMEChainTerminal(msg, qName, qtype, sets, chain, now)
		switch res {
		case dnssec.Bogus:
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

// judgeNegativeAuthority authenticates the non-denial Authority RRsets that
// are relevant to a negative answer. NSEC/NSEC3 were checked by the denial
// routines; SOA controls negative-cache lifetime and must not be allowed to
// remain an unvalidated claim under an AD response. RFC 4035 section 3.2.3
// requires relevant negative Authority RRsets to be authentic.
//
// Some recursive upstreams omit SOA despite returning a usable denial proof,
// so absence is not promoted to a new validation failure here. If one is
// supplied, however, its RRSIG must verify.
func (plugin *PluginDNSSECValidate) judgeNegativeAuthority(msg *dns.Msg, chain dnssec.ChainResult, now time.Time) (dnssec.Result, error) {
	for _, set := range dnssec.GroupRRSets(msg.Ns) {
		if set.Type != dns.TypeSOA {
			continue
		}
		if res, err := plugin.judgeSet(set, chain, msg, now); res != dnssec.Secure {
			return res, err
		}
	}
	return dnssec.Secure, nil
}

// judgeNegative validates an answer with no ordinary RRsets.  An authenticated
// denial is signed by the zone that generated the NSEC/NSEC3 proof, not by a
// made-up zone at every label of the queried name.  In particular, an NXDOMAIN
// below signed tor.dan.me.uk. has to build a chain to tor.dan.me.uk., rather
// than trying to establish whether each nonexistent address label is itself a
// delegation.
//
// RFC 4035 sections 5.3.1 and 5.4 make the signer's zone the authoritative
// source of the denial.  We still verify both the chain and the denial before
// trusting it; the untrusted Signer's Name merely selects which chain to try.
func (plugin *PluginDNSSECValidate) judgeNegative(msg *dns.Msg, qName string, now time.Time) (dnssec.Result, error) {
	zones := negativeDenialSignerZones(msg.Ns, qName)
	if len(zones) == 0 {
		// An unsigned negative response has no denial signer to follow.  The
		// chain to the name is then the only way to distinguish an ordinary
		// unsigned delegation from a response missing the proof it owes us.
		return plugin.judgeNegativeWithChain(msg, qName, dnssec.BuildChain(plugin.fetcher, qName, plugin.anchors, now), now)
	}

	// A response can carry more than one authenticated denial signature during
	// a key rollover.  Accept the first fully validated proof, but do not let a
	// failed candidate hide a valid one from the same response.
	var worst dnssec.Result = dnssec.Indeterminate
	var worstErr error
	for _, zone := range zones {
		chain := dnssec.BuildChain(plugin.fetcher, zone, plugin.anchors, now)
		result, err := plugin.judgeNegativeWithChain(msg, qName, chain, now)
		if result == dnssec.Secure || result == dnssec.Insecure {
			return result, err
		}
		if result == dnssec.Bogus || worstErr == nil {
			worst, worstErr = result, err
		}
	}
	return worst, worstErr
}

// negativeDenialSignerZones returns the zones that claim to have signed the
// NSEC/NSEC3 evidence for qName.  Requiring each candidate to enclose qName
// prevents an unrelated authority record from steering the chain walk.  The
// candidate is not trusted until judgeNegativeWithChain verifies its DNSKEY
// chain and the actual denial RRset.
func negativeDenialSignerZones(authority []dns.RR, qName string) []string {
	zones := make([]string, 0, 1)
	seen := make(map[string]struct{})
	for _, rr := range authority {
		sig, ok := rr.(*dns.RRSIG)
		if !ok || (sig.TypeCovered != dns.TypeNSEC && sig.TypeCovered != dns.TypeNSEC3) ||
			!dnssec.WithinZone(qName, sig.SignerName) {
			continue
		}
		zone := strings.ToLower(sig.SignerName)
		if _, ok := seen[zone]; ok {
			continue
		}
		seen[zone] = struct{}{}
		zones = append(zones, zone)
	}
	return zones
}

// judgeNegativeWithChain validates a negative answer against an already
// selected chain.  Keeping the proof check separate from chain selection makes
// it impossible for a Signer's Name alone to authenticate a denial.
func (plugin *PluginDNSSECValidate) judgeNegativeWithChain(msg *dns.Msg, qName string, chain dnssec.ChainResult, now time.Time) (dnssec.Result, error) {
	switch chain.Status {
	case dnssec.Secure:
	case dnssec.Insecure:
		// The zone is unsigned, so there is nothing to check. Whether the
		// delegation saying so was itself genuine is checked while building
		// the chain.
		return dnssec.Insecure, nil
	case dnssec.Bogus:
		return dnssec.Bogus, chain.Why
	default:
		return dnssec.Indeterminate, chain.Why
	}
	denial := dnssec.CollectDenial(msg.Ns).Verified(chain.Keys, chain.Zone, now)
	if denial.Empty() {
		return dnssec.Bogus, fmt.Errorf("%w: a signed zone answered nothing and proved nothing", errDNSSECIncompleteEvidence)
	}
	qtype := dns.RRToType(msg.Question[0])
	if msg.Rcode == dns.RcodeNameError {
		if denial.ProvesNameError(qName, chain.Zone) {
			return plugin.judgeNegativeAuthority(msg, chain, now)
		}
		if denial.HasOnlyUnsupportedNSEC3Iterations() {
			return dnssec.Indeterminate, dnssec.ErrUnsupportedNSEC3Iterations
		}
		return dnssec.Bogus, fmt.Errorf("%w: no proof that %s does not exist", errDNSSECIncompleteEvidence, qName)
	}
	if denial.ProvesNoData(qName, qtype) {
		return plugin.judgeNegativeAuthority(msg, chain, now)
	}
	if denial.ProvesWildcardNoData(qName, chain.Zone, qtype) {
		return plugin.judgeNegativeAuthority(msg, chain, now)
	}
	if denial.HasOnlyUnsupportedNSEC3Iterations() {
		return dnssec.Indeterminate, dnssec.ErrUnsupportedNSEC3Iterations
	}
	return dnssec.Bogus, fmt.Errorf("%w: no proof that %s holds no record of this type", errDNSSECIncompleteEvidence, qName)
}

// judgeCNAMEChainTerminal authenticates the final negative answer behind a
// CNAME chain. RFC 4035 section 3.2.3 permits AD only when all answer RRsets
// and relevant negative authority RRsets are authentic. It returns Secure
// without further work when the answer contains no chain from qname, or when
// the chain terminates in the requested RRset.
func (plugin *PluginDNSSECValidate) judgeCNAMEChainTerminal(msg *dns.Msg, qName string, qtype uint16, sets []dnssec.RRSet, chain dnssec.ChainResult, now time.Time) (dnssec.Result, error) {
	terminal, followed, err := cnameChainTerminal(qName, sets)
	if err != nil {
		return dnssec.Bogus, err
	}
	if !followed || hasRRSet(sets, terminal, qtype) {
		return dnssec.Secure, nil
	}
	// A CNAME-only response is a legitimate intermediate positive response: a
	// client or recursive upstream may continue with the target separately. It
	// becomes a negative answer only when it carries NXDOMAIN or authenticated
	// denial material for the terminal name.
	if msg.Rcode != dns.RcodeNameError && !hasSOA(msg.Ns) && dnssec.CollectDenial(msg.Ns).Empty() {
		return dnssec.Secure, nil
	}

	// The authority proof belongs to the zone that signed its NSEC/NSEC3
	// RRsets, which can be above the terminal name by several non-zone-cut
	// labels.  Use the same signer-directed path as a wholly negative answer;
	// walking directly to terminal would reject valid deep negative CNAME
	// targets for the same reason.
	return plugin.judgeNegative(msg, terminal, now)
}

// cnameChainTerminal follows the CNAME RRsets actually included in an answer.
// A CNAME RRset has one target; multiple targets or a loop cannot be a
// meaningful answer and must not be redeemed by a signed unrelated RRset.
func cnameChainTerminal(qName string, sets []dnssec.RRSet) (terminal string, followed bool, err error) {
	terminal = qName
	seen := map[string]bool{}
	for {
		key := dnsNameKey(terminal)
		if seen[key] {
			return "", false, fmt.Errorf("CNAME loop at %s", terminal)
		}
		seen[key] = true

		var cnames []*dns.CNAME
		for _, set := range sets {
			if set.Type != dns.TypeCNAME || !sameDNSName(set.Name, terminal) {
				continue
			}
			for _, rr := range set.Records {
				cname, ok := rr.(*dns.CNAME)
				if !ok {
					return "", false, fmt.Errorf("CNAME RRset at %s contains %T", terminal, rr)
				}
				cnames = append(cnames, cname)
			}
		}
		if len(cnames) == 0 {
			return terminal, followed, nil
		}
		if len(cnames) != 1 {
			return "", false, fmt.Errorf("CNAME RRset at %s has %d targets", terminal, len(cnames))
		}
		followed = true
		terminal = cnames[0].Target
	}
}

// dnsNameKey matches the internal query-name representation: query plugins
// deliberately retain names without a trailing root label, while names in DNS
// RRs are fully qualified. The vendored DNS library's EqualName requires two
// fully-qualified inputs and panics when given the former. DNSCrypt only
// accepts ASCII query names (NormalizeQName), and this library does not
// support escaped presentation names, so case-folding and one trailing root
// label are the complete DNS-name canonicalization needed here.
func dnsNameKey(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func sameDNSName(a, b string) bool {
	return dnsNameKey(a) == dnsNameKey(b)
}

func hasRRSet(sets []dnssec.RRSet, name string, rrtype uint16) bool {
	for _, set := range sets {
		if set.Type == rrtype && sameDNSName(set.Name, name) {
			return true
		}
	}
	return false
}

func hasSOA(rrs []dns.RR) bool {
	for _, rr := range rrs {
		if dns.RRToType(rr) == dns.TypeSOA {
			return true
		}
	}
	return false
}

type validatedDNAME struct {
	record *dns.DNAME
	result dnssec.Result
	err    error
}

// synthesizedCNAMEFromDNAME recognizes the CNAME generated by DNAME
// substitution. It accepts no unsigned CNAME merely because a DNAME happened
// to be present: owner and target must be the exact replacement RFC 6672
// defines, and the DNAME's own validation result is inherited.
func synthesizedCNAMEFromDNAME(set dnssec.RRSet, dnames []validatedDNAME) (dnssec.Result, error, bool) {
	if set.Type != dns.TypeCNAME || len(set.Sigs) != 0 || len(set.Records) != 1 {
		return dnssec.Indeterminate, nil, false
	}
	cname, ok := set.Records[0].(*dns.CNAME)
	if !ok {
		return dnssec.Indeterminate, nil, false
	}
	for _, candidate := range dnames {
		if !dnameAppliesToName(candidate.record, cname.Header().Name) {
			continue
		}
		if dnameSynthesizesCNAME(candidate.record, cname) {
			return candidate.result, candidate.err, true
		}
		if candidate.result == dnssec.Secure {
			return dnssec.Bogus, fmt.Errorf(
				"unsigned CNAME %s is not the synthesis of secure DNAME %s",
				cname.Header().Name, candidate.record.Header().Name), true
		}
		return candidate.result, candidate.err, true
	}
	return dnssec.Indeterminate, nil, false
}

func dnameSynthesizesCNAME(dname *dns.DNAME, cname *dns.CNAME) bool {
	if !dnameAppliesToName(dname, cname.Header().Name) {
		return false
	}
	ownerName := strings.TrimSuffix(strings.ToLower(dname.Header().Name), ".")
	ownerLabels := strings.Split(ownerName, ".")
	cnameName := strings.TrimSuffix(strings.ToLower(cname.Header().Name), ".")
	cnameLabels := strings.Split(cnameName, ".")
	prefix := cnameLabels[:len(cnameLabels)-len(ownerLabels)]
	target := strings.TrimSuffix(strings.ToLower(dname.Target), ".")
	expectedLabels := append(prefix, strings.Split(target, ".")...)
	expected := "."
	if target != "" {
		expected = strings.Join(expectedLabels, ".") + "."
	}
	return dns.EqualName(cname.Target, expected)
}

func dnameAppliesToName(dname *dns.DNAME, name string) bool {
	ownerName := strings.TrimSuffix(strings.ToLower(dname.Header().Name), ".")
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if ownerName == "" || name == "" {
		return false
	}
	ownerLabels := strings.Split(ownerName, ".")
	nameLabels := strings.Split(name, ".")
	if len(nameLabels) <= len(ownerLabels) {
		return false
	}
	for i := range ownerLabels {
		if nameLabels[len(nameLabels)-len(ownerLabels)+i] != ownerLabels[i] {
			return false
		}
	}
	return true
}

// judgeSet checks one RRset against the authenticated zone containing it.
//
// RFC 4035 section 5.3.1 requires the RRSIG Signer's Name to be the zone that
// contains the RRset, not merely an ancestor of its owner. A parent can sign
// arbitrary bytes with its own key; accepting that signature below a delegated
// child would let it impersonate the child. The chain walk establishes the
// actual containing zone and the RRSIG must name that exact zone.
func (plugin *PluginDNSSECValidate) judgeSet(set dnssec.RRSet, chain dnssec.ChainResult, msg *dns.Msg, now time.Time) (dnssec.Result, error) {
	if len(set.Sigs) == 0 {
		// Nothing claims to have signed this. Whether that is a forgery or an
		// ordinary unsigned answer depends on whether the zone holding the name
		// signs at all, which is what the walk to the name decides.
		owner := plugin.chainFor(set.Name, chain, now)
		switch owner.Status {
		case dnssec.Secure:
			return dnssec.Bogus, fmt.Errorf("%w: %s is signed, but its %s record for %s is not", errDNSSECIncompleteEvidence,
				owner.Zone, dns.TypeToString[set.Type], set.Name)
		case dnssec.Insecure:
			return dnssec.Insecure, owner.Why
		case dnssec.Bogus:
			return dnssec.Bogus, owner.Why
		default:
			return dnssec.Indeterminate, owner.Why
		}
	}

	owner := plugin.chainFor(set.Name, chain, now)
	switch owner.Status {
	case dnssec.Secure:
	case dnssec.Insecure:
		return dnssec.Insecure, owner.Why
	case dnssec.Bogus:
		return dnssec.Bogus, owner.Why
	default:
		return dnssec.Indeterminate, owner.Why
	}

	var lastErr error
	for _, sig := range set.Sigs {
		if !dns.EqualName(owner.Zone, sig.SignerName) {
			lastErr = fmt.Errorf("%s belongs to %s, not %s", set.Name, owner.Zone, sig.SignerName)
			continue
		}
		res, verified, err := dnssec.VerifyRRSetDetail(set.Records, []*dns.RRSIG{sig}, owner.Keys, now)
		if res == dnssec.Secure {
			// RFC 4035 section 5.3.3: a signature made over a wildcard verifies
			// for every name beneath it, so it is evidence that the wildcard
			// exists rather than that it was the right answer here. The zone
			// has to have shown that nothing closer to the name does exist.
			if nextCloser, expanded := dnssec.WildcardNextCloser(verified, set.Name); expanded {
				denial := dnssec.CollectDenial(msg.Ns).Verified(owner.Keys, owner.Zone, now)
				if !denial.ProvesNoCloserMatch(nextCloser) {
					if denial.HasOnlyUnsupportedNSEC3Iterations() {
						return dnssec.Indeterminate, dnssec.ErrUnsupportedNSEC3Iterations
					}
					return dnssec.Bogus, fmt.Errorf(
						"%s was answered from a wildcard in %s with no proof that %s does not exist",
						set.Name, owner.Zone, nextCloser)
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
	pluginsState.sessionData[dnssecClientCheckingDisabledKey] = msg.CheckingDisabled
	// RFC 4035 section 4.6 requires a resolver to clear AD in an outgoing
	// query. The client bit is only a request to receive our verdict; sending
	// it upstream lets a buggy server reflect a client-controlled assertion.
	msg.AuthenticatedData = false
	msg.Security = true
	// RFC 6840 section 5.9 recommends CD on every upstream query. We validate
	// the raw response locally, so an upstream validator must not replace it
	// with SERVFAIL first. Keep the client's original bit separately and put it
	// back before replying.
	msg.CheckingDisabled = true
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

// dnssecClientCheckingDisabledKey keeps the client's CD bit while the proxy
// sets CD on its own upstream query to retrieve raw material for validation.
const dnssecClientCheckingDisabledKey = "dnssec_client_checking_disabled"

// dnssecVerdictKey and dnssecReasonKey carry what validation concluded about an
// answer, and why, to whatever reports on the query afterwards. The wire has
// room for the verdict alone, as one bit; anyone looking at a dashboard to find
// out why a name will not resolve needs the sentence.
const (
	dnssecVerdictKey = "dnssec_verdict"
	dnssecReasonKey  = "dnssec_reason"
)

// modeName is how the mode is written for a reader.
func modeName(mode ValidationMode) string {
	switch mode {
	case ValidationEnforce:
		return "enforce"
	case ValidationLog:
		return "log"
	default:
		return "off"
	}
}

// verdictName is how a verdict is written for a reader.
func verdictName(result dnssec.Result) string {
	switch result {
	case dnssec.Secure:
		return "secure"
	case dnssec.Bogus:
		return "bogus"
	case dnssec.Insecure:
		return "insecure"
	default:
		return "indeterminate"
	}
}

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
	restoreDNSSECClientBits(pluginsState, msg)
	wanted, _ := pluginsState.sessionData[dnssecClientWantedKey].(bool)
	askedForVerdict, _ := pluginsState.sessionData[dnssecClientAskedADKey].(bool)
	if !wanted {
		stripDNSSECRecords(msg)
	}
	if !wanted && !askedForVerdict {
		msg.AuthenticatedData = false
	}
}

// restoreDNSSECClientBits removes the two upstream-only query mutations from
// a client-facing reply. RFC 3225 section 3 requires DO to be copied from the
// client query, while RFC 4035 section 3.2.2 says the same for CD. The
// validator sets both on its upstream query so it can obtain unfiltered DNSSEC
// material; neither change may leak back to the client.
func restoreDNSSECClientBits(pluginsState *PluginsState, msg *dns.Msg) {
	if wanted, ok := pluginsState.sessionData[dnssecClientWantedKey].(bool); ok {
		msg.Security = wanted
	}
	if checkingDisabled, ok := pluginsState.sessionData[dnssecClientCheckingDisabledKey].(bool); ok {
		msg.CheckingDisabled = checkingDisabled
	}
}

func clientCheckingDisabled(pluginsState *PluginsState) bool {
	if checkingDisabled, ok := pluginsState.sessionData[dnssecClientCheckingDisabledKey].(bool); ok {
		return checkingDisabled
	}
	return pluginsState.questionMsg != nil && pluginsState.questionMsg.CheckingDisabled
}
