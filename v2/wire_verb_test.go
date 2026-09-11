package tdnsmp

// wireVerb returns the verb the production parser extracts from a payload
// ("" when it cannot be parsed); appVerbKnown reports whether the verb
// table has a row for it (transport-own or application).
func wireVerb(payload []byte) string {
	m, err := parseAppPayload("", payload, "")
	if err != nil {
		return ""
	}
	return m.Token()
}

func appVerbKnown(token string) bool {
	for i := range appVerbRegistry {
		if appVerbRegistry[i].token == token {
			return true
		}
	}
	return false
}
