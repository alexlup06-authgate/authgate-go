package authgate

import (
	"errors"
)

// SDK is the main entry point for the AuthGate Go SDK.
//
// It holds the internal verifier used to validate AuthGate-issued
// access tokens and to power the provided HTTP middleware.
type SDK struct {
	verifier *verifier
}

// New initializes a new AuthGate SDK instance using the provided configuration.
//
// All fields of Config are required. New performs validation and returns
// an error if the configuration is incomplete or invalid.
//
// Example:
//
//	sdk, err := authgate.New(authgate.Config{
//		Issuer:   "https://example.com",
//		Audience: "app",
//		Keys:     keys,
//	})
func New(cfg Config) (*SDK, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("authgate: issuer is required")
	}

	if cfg.Audience == "" {
		return nil, errors.New("authgate: audience is required")
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
