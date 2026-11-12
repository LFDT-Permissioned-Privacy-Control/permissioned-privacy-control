package v2server

// These are pinned deployment bindings, not request-selectable endpoints. The
// immutable Core documents still decide groups, method rights and raw mode.
type Credential struct {
	FromEnv string `json:"fromEnv"`
	Header  string `json:"header"`
}
type Endpoint struct {
	URL         string      `json:"url"`
	PragueStart uint64      `json:"pragueStart"`
	PragueEnd   uint64      `json:"pragueEnd"`
	Credential  *Credential `json:"credential,omitempty" optional:"true"`
}
type Node struct {
	OrganizationID       string       `json:"organizationId"`
	URL                  string       `json:"url"`
	PragueStart          uint64       `json:"pragueStart"`
	PragueEnd            uint64       `json:"pragueEnd"`
	AllowUnauthenticated bool         `json:"allowUnauthenticated"`
	Credentials          []Credential `json:"credentials"`
	Guard                *Guard       `json:"guard,omitempty" optional:"true"`
}
type Guard struct {
	SeedEnv            string   `json:"seedEnv"`
	KeyID              string   `json:"keyId"`
	Targets            []string `json:"targets"`
	HashMode           uint8    `json:"hashMode"`
	MaxBatch           int      `json:"maxBatch"`
	ApprovalTTLSeconds int      `json:"approvalTTLSeconds"`
}
type Admission struct {
	AppDSNEnv              string `json:"appDSNEnv"`
	ReaderDSNEnv           string `json:"readerDSNEnv"`
	FactsDSNEnv            string `json:"factsDSNEnv"`
	Generation             string `json:"generation"`
	CoverageDigest         string `json:"coverageDigest"`
	AddressSourceSetDigest string `json:"addressSourceSetDigest"`
	AddressReferenceDigest string `json:"addressReferenceDigest"`
	CursorKeyEnv           string `json:"cursorKeyEnv"`
	CursorKeyID            string `json:"cursorKeyId"`
}
type Activity struct {
	WriterDSNEnv        string `json:"writerDSNEnv"`
	ReaderDSNEnv        string `json:"readerDSNEnv"`
	SourceID            string `json:"sourceId"`
	ProducerID          string `json:"producerId"`
	Generation          string `json:"generation"`
	ConfigurationDigest string `json:"configurationDigest"`
	BufferDirectory     string `json:"bufferDirectory"`
}
type Index struct {
	ReaderDSNEnv          string `json:"readerDSNEnv"`
	SourceReferenceDigest string `json:"sourceReferenceDigest"`
	ConfiguredEpoch       string `json:"configuredEpoch"`
	CursorKeyEnv          string `json:"cursorKeyEnv"`
	PseudonymKeyEnv       string `json:"pseudonymKeyEnv"`
}
type Data struct {
	NodeSigning               bool      `json:"nodeSigning"`
	PriceFeedCredentialHeader string    `json:"priceFeedCredentialHeader,omitempty" optional:"true"`
	PriceFeedAllowPrivate     bool      `json:"priceFeedAllowPrivate"`
	DefaultNode               Endpoint  `json:"defaultNode"`
	Nodes                     []Node    `json:"nodes"`
	WalletReaderDSNEnv        string    `json:"walletReaderDSNEnv"`
	Admission                 Admission `json:"admission"`
	Activity                  Activity  `json:"activity"`
	Index                     Index     `json:"index"`
	MetadataPolicy            File      `json:"metadataPolicy"`
	StatePolicy               File      `json:"statePolicy"`
	HistoryPolicy             File      `json:"historyPolicy"`
}
