package config

import (
	"time"

	"github.com/spf13/pflag"
)

type Config struct {
	KubeconfigFile        string
	KubernetesMaster      string
	AppPort               string
	DefaultServiceAccount string
	ServiceAccountKey     string
	MetadataAddress       string
	HostInterface         string
	HostIP                string
	NamespaceKey          string
	LogLevel              string
	AttributeWhitelist    []string
	AttributeWhitelistSet map[string]struct{}
	AddIPTablesRule       bool
	Debug                 bool
	Insecure              bool
	NamespaceRestriction  bool
	Verbose               bool
	Version               bool
	BackoffMaxInterval    time.Duration
	BackoffMaxElapsedTime time.Duration
}

func Load() *Config {
	cfg := &Config{
		AppPort:               "8181",
		ServiceAccountKey:     "cloud.google.com/service-account",
		LogLevel:              "info",
		BackoffMaxElapsedTime: 2 * time.Second,
		BackoffMaxInterval:    1 * time.Second,
		MetadataAddress:       "169.254.169.254",
		HostIP:                "127.0.0.1",
		NamespaceKey:          "cloud.google.com/allowed-service-accounts",
	}

	fs := pflag.CommandLine
	fs.StringVar(&cfg.KubeconfigFile, "kubeconfig", cfg.KubeconfigFile, "Absolute path to the kubeconfig file")
	fs.StringVar(&cfg.KubernetesMaster, "server", cfg.KubernetesMaster, "The address and port of the Kubernetes API server")
	fs.StringVar(&cfg.AppPort, "app-port", cfg.AppPort, "Http port")
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "Enable debug features")
	fs.StringVar(&cfg.DefaultServiceAccount, "default-service-account", cfg.DefaultServiceAccount, "Fallback service account to use when annotation is not set")
	fs.StringVar(&cfg.ServiceAccountKey, "service-account-key", cfg.ServiceAccountKey, "Pod annotation key used to retrieve the service account")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "Kubernetes server should be accessed without verifying the TLcfg. Testing only")
	fs.StringVar(&cfg.MetadataAddress, "metadata-addr", cfg.MetadataAddress, "Address for the metadata service.")
	fs.StringSliceVar(&cfg.AttributeWhitelist, "attributes", cfg.AttributeWhitelist, "Metadata attribute whitelist to pass through to the clients")
	fs.BoolVar(&cfg.AddIPTablesRule, "iptables", false, "Add iptables rule (also requires --host-ip)")
	fs.StringVar(&cfg.HostInterface, "host-interface", "docker0", "Interface on which to enable the iptables rule")
	fs.BoolVar(&cfg.NamespaceRestriction, "namespace-restrictions", false, "Enable namespace restrictions")
	fs.StringVar(&cfg.NamespaceKey, "namespace-key", cfg.NamespaceKey, "Namespace annotation key used to retrieve the allowed service accounts (value in annotation should be json array)")
	fs.StringVar(&cfg.HostIP, "host-ip", cfg.HostIP, "IP address of host")
	fs.DurationVar(&cfg.BackoffMaxInterval, "backoff-max-interval", cfg.BackoffMaxInterval, "Max interval for backoff when querying for service account.")
	fs.DurationVar(&cfg.BackoffMaxElapsedTime, "backoff-max-elapsed-time", cfg.BackoffMaxElapsedTime, "Max elapsed time for backoff when querying for service account.")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "Verbose")
	fs.BoolVar(&cfg.Version, "version", false, "Print the version and exits")
	pflag.Parse()

	cfg.AttributeWhitelistSet = make(map[string]struct{})
	for _, a := range cfg.AttributeWhitelist {
		cfg.AttributeWhitelistSet[a] = struct{}{}
	}

	return cfg
}
