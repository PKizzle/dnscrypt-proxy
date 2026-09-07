package main

import "codeberg.org/miekg/dns"

type PluginGetSetPayloadSize struct{}

func (plugin *PluginGetSetPayloadSize) Name() string {
	return "get_set_payload_size"
}

func (plugin *PluginGetSetPayloadSize) Description() string {
	return "Adjusts the maximum payload size advertised in queries sent to upstream servers."
}

func (plugin *PluginGetSetPayloadSize) Init(proxy *Proxy) error {
	return nil
}

func (plugin *PluginGetSetPayloadSize) Drop() error {
	return nil
}

func (plugin *PluginGetSetPayloadSize) Reload() error {
	return nil
}

func (plugin *PluginGetSetPayloadSize) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	pluginsState.originalMaxPayloadSize = 512 - ResponseOverhead
	pluginsState.maxUnencryptedUDPSafePayloadSize = dns.MinMsgSize

	// In v2, EDNS0 info is directly on msg. Earlier query plugins may have
	// added or enlarged OPT for the upstream transaction, so use the state
	// captured immediately after unpacking when deciding what the client can
	// receive. RFC 6891 section 6.2.3 says advertised sizes below 512 are
	// treated as 512; a client without EDNS is likewise limited to classic DNS's
	// 512-byte UDP message size.
	clientHadEDNS := messageHasEDNS(msg)
	clientUDPSize := msg.UDPSize
	if pluginsState.clientEDNSStateRecorded {
		clientHadEDNS = pluginsState.clientHadEDNS
		clientUDPSize = pluginsState.clientUDPSize
	}
	dnssec := msg.Security
	if clientHadEDNS {
		pluginsState.maxUnencryptedUDPSafePayloadSize = Max(int(clientUDPSize), dns.MinMsgSize)
		pluginsState.originalMaxPayloadSize = Max(
			pluginsState.maxUnencryptedUDPSafePayloadSize-ResponseOverhead,
			pluginsState.originalMaxPayloadSize,
		)
	}

	pluginsState.dnssec = dnssec
	pluginsState.maxPayloadSize = Min(
		MaxDNSUDPPacketSize-ResponseOverhead,
		Max(pluginsState.originalMaxPayloadSize, pluginsState.maxPayloadSize),
	)

	if pluginsState.maxPayloadSize > 512 {
		// Set the EDNS0 parameters on msg directly
		msg.UDPSize = uint16(pluginsState.maxPayloadSize)
		msg.Security = dnssec
	}

	return nil
}
