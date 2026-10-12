package main

import (
	"codeberg.org/miekg/dns"
)

// extendedErrorBlamesZone reports whether an extended DNS error (RFC 8914)
// attributes a failure to the queried name, its zone or its DNSSEC chain
// rather than to the server that answered. Another upstream would fail such a
// name the same way, and the server demonstrably processed the query, so the
// answer says nothing about the server's health. Codes about the server's own
// state, codes that only annotate successful answers, and codes this build
// does not know are attributed to the server.
func extendedErrorBlamesZone(code uint16) bool {
	switch code {
	case dns.ExtendedErrorUnsupportedDNSKEYAlgorithm,
		dns.ExtendedErrorUnsupportedDSDigestType,
		dns.ExtendedErrorDNSSECIndeterminate,
		dns.ExtendedErrorDNSBogus,
		dns.ExtendedErrorSignatureExpired,
		dns.ExtendedErrorSignatureNotYetValid,
		dns.ExtendedErrorDNSKEYMissing,
		dns.ExtendedErrorRRSIGsMissing,
		dns.ExtendedErrorNoZoneKeyBitSet,
		dns.ExtendedErrorNSECMissing,
		dns.ExtendedErrorCachedError,
		dns.ExtendedErrorBlocked,
		dns.ExtendedErrorCensored,
		dns.ExtendedErrorFiltered,
		dns.ExtendedErrorProhibited,
		dns.ExtendedErrorNoReachableAuthority,
		dns.ExtendedErrorInvalidData,
		dns.ExtendedErrorSignatureExpiredBeforeValid,
		dns.ExtendedErrorUnsupportedNSEC3IterValue,
		dns.ExtendedErrorInvalidQueryType:
		return true
	}
	return false
}

// servfailBlamesZone reports whether a packed SERVFAIL carries an extended
// DNS error that attributes the failure to the zone. A response that is not a
// SERVFAIL, carries no such error, or does not parse is attributed to the
// server.
func servfailBlamesZone(response []byte) bool {
	if len(response) < MinDNSPacketSize || Rcode(response) != dns.RcodeServerFailure {
		return false
	}
	msg := dns.Msg{Data: response}
	if err := msg.Unpack(); err != nil {
		return false
	}
	for _, rr := range msg.Pseudo {
		if ede, ok := rr.(*dns.EDE); ok && extendedErrorBlamesZone(ede.InfoCode) {
			return true
		}
	}
	return false
}
