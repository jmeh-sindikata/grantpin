package mcp

// daemonEnvKeys is the allow-list of environment variables forwarded to an
// auto-started daemon: just enough to locate the user's home, binaries and
// runtime/data directories. Everything else (including GRANTD_*, tokens, API
// keys) is dropped.
var daemonEnvKeys = []string{
	"HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "LANG",
	"XDG_RUNTIME_DIR", "XDG_DATA_HOME", "XDG_CONFIG_HOME",
	"DBUS_SESSION_BUS_ADDRESS", // Linux Secret Service backends
}

func daemonEnv(getenv func(string) string) []string {
	var env []string
	for _, k := range daemonEnvKeys {
		if v := getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}
