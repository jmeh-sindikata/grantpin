package darwin

// Option configures New.
type Option func(*config)

type config struct {
	allowFallback bool
}

// WithAllowKeychainFallback permits using a Keychain-resident AES KEK when the
// Secure Enclave is unavailable. Default false: New/Wrap refuse with
// ErrSecureEnclaveUnavailable rather than silently weaken protection. In
// fallback mode Tier() is presence.TierDialog.
func WithAllowKeychainFallback(allow bool) Option {
	return func(c *config) { c.allowFallback = allow }
}

func newConfig(opts []Option) config {
	var c config
	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}
	return c
}
