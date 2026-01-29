package authgate

import (
	"errors"
)

type SDK struct {
	verifier *verifier
}

func New(cfg Config) (*SDK, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("authgate: issuer is required")
	}

	if len(cfg.Keys) == 0 {
		return nil, errors.New("authgate: at least one key is required")
	}

	v, err := newVerifier(cfg)
	if err != nil {
		return nil, err
	}

	return &SDK{verifier: v}, nil
}
