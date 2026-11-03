package rule

// Registry returns the generic rules in output order (ADR-002 section 5.2):
// id-prefix, ip-address, email-address. ids is the caller's identity allowance,
// a list of addresses already checked against section 5.4's form, or nil for
// none. cmd/hush appends the term sets after these.
func Registry(ids []string) List {
	return List{IDPrefix{}, IPAddress{}, NewEmailAddress(ids)}
}
