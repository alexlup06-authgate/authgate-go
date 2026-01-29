package authgate

type Config struct {
	Issuer   string
	Audience string
	Keys     map[string][]byte
}
