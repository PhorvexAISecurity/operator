package identityfixture

// GenerateInput carries the installed-fixture facts the profile generator reads
// from a live cluster. Every field is an authoritative object fact, never a
// caller-supplied tenant claim: the namespace UID and policy UID/generation pin
// the exact fixture the operator will later observe.
type GenerateInput struct {
	JournalNamespace string
	Namespace        string
	NamespaceUID     string
	PolicyName       string
	PolicyUID        string
	PolicyGeneration int64
	Cluster          string
	Region           string
}

// NewProfile validates the reviewed fixture contract before emitting a profile.
// Validation is the same Validate() the loader and observer use, so a generated
// profile can never be weaker than the runtime requirement.
func (in GenerateInput) NewProfile() (Profile, error) {
	p := Profile{
		JournalNamespace: in.JournalNamespace,
		Namespace:        in.Namespace,
		NamespaceUID:     in.NamespaceUID,
		PolicyName:       in.PolicyName,
		PolicyUID:        in.PolicyUID,
		PolicyGeneration: in.PolicyGeneration,
		Cluster:          in.Cluster,
		Region:           in.Region,
	}
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}
