package main

import (
	"fmt"
	"strings"
	"sync"
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

	mu      sync.Mutex
	secure  uint64
	bogus   uint64
	unknown uint64
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

	plugin.mu.Lock()
	switch result {
	case dnssec.Secure:
		plugin.secure++
	case dnssec.Bogus:
		plugin.bogus++
	default:
		plugin.unknown++
	}
	plugin.mu.Unlock()

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
	chain := dnssec.BuildChain(plugin.fetcher, qName, plugin.anchors, time.Now())
	switch chain.Status {
	case dnssec.Secure:
	case dnssec.Insecure:
		// The zone is unsigned, so there is nothing to check. Whether the
		// delegation saying so was itself genuine is what the denial proofs
		// decide, and that is checked where the delegation is read.
		return dnssec.Insecure, nil
	default:
		// A chain that could not be built is not evidence that an answer is
		// forged. Refusing here would take the resolver down whenever the path
		// to the root is unreachable.
		return dnssec.Indeterminate, chain.Why
	}

	records, sigs := dnssec.SplitSignatures(msg.Answer)
	if len(records) == 0 {
		// Nothing was answered: the zone should have proved why.
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

	res, err := dnssec.VerifyRRSet(records, sigs, chain.Keys, time.Now())
	if res == dnssec.Secure {
		return dnssec.Secure, nil
	}
	if err == dnssec.ErrNoSignature {
		// A signed zone that answers without a signature is the case this
		// exists to catch: an unsigned answer for a name whose zone signs.
		return dnssec.Bogus, fmt.Errorf("%s is signed, but this answer is not", chain.Zone)
	}
	return res, err
}
