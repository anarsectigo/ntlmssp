package ntlmssp

// Test bridge.
//
// The sealed request and response paths can only be exercised with a client that has
// already completed a handshake and a matching session on the other side. Both the
// session constructor and the Client fields that hold it are unexported, so there is
// no way to assemble that from an external test — which is why the replay and
// serialization behaviour in the http subpackage had no coverage at all.
//
// These two functions exist for tests and nothing else. They take a caller-supplied
// session key so fixtures are deterministic and no real key material is involved.

// NewSecuritySessionPair returns the client-side and server-side halves of a security
// session derived from the same exported session key, as a completed handshake would
// produce. What one seals, the other unseals.
func NewSecuritySessionPair(flags uint32, exportedSessionKey []byte) (client, server *SecuritySession, err error) {
	client, err = newSecuritySession(flags, exportedSessionKey, sourceClient)
	if err != nil {
		return nil, nil, err
	}
	server, err = newSecuritySession(flags, exportedSessionKey, sourceServer)
	if err != nil {
		return nil, nil, err
	}
	return client, server, nil
}

// SetTestSession is a Client option that marks the client complete and installs a
// session built from the given key, standing in for a handshake. The matching
// server-side session comes from NewSecuritySessionPair with the same arguments.
func SetTestSession(flags uint32, exportedSessionKey []byte) func(*Client) error {
	return func(c *Client) error {
		session, err := newSecuritySession(flags, exportedSessionKey, sourceClient)
		if err != nil {
			return err
		}
		c.negotiatedFlags = flags
		c.securitySession = session
		c.complete = true
		return nil
	}
}

// TestSessionFlags is the flag set these helpers are meant to be used with: NTLMv2
// with extended session security, sealing and signing on, which is what WinRM
// negotiates and therefore the only combination the sealed paths care about.
const TestSessionFlags = uint32(ntlmsspNegotiateSeal) |
	uint32(ntlmsspNegotiateSign) |
	uint32(ntlmsspNegotiateExtendedSessionsecurity) |
	uint32(ntlmsspNegotiateKeyExch)
