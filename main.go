package main

import (
	"github.com/KernelPay/kube-google-iam/iptables"
	"github.com/KernelPay/kube-google-iam/server"
	"github.com/KernelPay/kube-google-iam/version"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

// addFlags adds the command line flags.
func addFlags(s *server.Server, fs *pflag.FlagSet) {
	fs.StringVar(&s.KubeconfigFile, "kubeconfig", s.KubeconfigFile, "Absolute path to the kubeconfig file")
	fs.StringVar(&s.KubernetesMaster, "server", s.KubernetesMaster, "The address and port of the Kubernetes API server")
	fs.StringVar(&s.AppPort, "app-port", s.AppPort, "Http port")
	fs.BoolVar(&s.Debug, "debug", s.Debug, "Enable debug features")
	fs.StringVar(&s.DefaultServiceAccount, "default-service-account", s.DefaultServiceAccount, "Fallback service account to use when annotation is not set")
	fs.StringVar(&s.ServiceAccountKey, "service-account-key", s.ServiceAccountKey, "Pod annotation key used to retrieve the service account")
	fs.BoolVar(&s.Insecure, "insecure", false, "Kubernetes server should be accessed without verifying the TLS. Testing only")
	fs.StringVar(&s.MetadataAddress, "metadata-addr", s.MetadataAddress, "Address for the metadata service.")
	fs.StringSliceVar(&s.AttributeWhitelist, "attributes", s.AttributeWhitelist, "Metadata attribute whitelist to pass through to the clients")
	fs.BoolVar(&s.AddIPTablesRule, "iptables", false, "Add iptables rule (also requires --host-ip)")
	fs.StringVar(&s.HostInterface, "host-interface", "docker0", "Interface on which to enable the iptables rule")
	fs.BoolVar(&s.NamespaceRestriction, "namespace-restrictions", false, "Enable namespace restrictions")
	fs.StringVar(&s.NamespaceKey, "namespace-key", s.NamespaceKey, "Namespace annotation key used to retrieve the allowed service accounts (value in annotation should be json array)")
	fs.StringVar(&s.HostIP, "host-ip", s.HostIP, "IP address of host")
	fs.DurationVar(&s.BackoffMaxInterval, "backoff-max-interval", s.BackoffMaxInterval, "Max interval for backoff when querying for service account.")
	fs.DurationVar(&s.BackoffMaxElapsedTime, "backoff-max-elapsed-time", s.BackoffMaxElapsedTime, "Max elapsed time for backoff when querying for service account.")
	fs.StringVar(&s.LogLevel, "log-level", s.LogLevel, "Log level")
	fs.BoolVar(&s.Verbose, "verbose", false, "Verbose")
	fs.BoolVar(&s.Version, "version", false, "Print the version and exits")
}

func main() {
	s := server.NewServer()
	addFlags(s, pflag.CommandLine)
	pflag.Parse()

	logLevel, err := log.ParseLevel(s.LogLevel)
	if err != nil {
		log.Fatalf("%s", err)
	}

	if s.Verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(logLevel)
	}

	if s.Version {
		version.PrintVersionAndExit()
	}

	if s.AddIPTablesRule {
		if err := iptables.AddRule(s.AppPort, s.MetadataAddress, s.HostInterface, s.HostIP); err != nil {
			log.Fatalf("%s", err)
		}
	}

	if err := s.Run(); err != nil {
		log.Fatalf("%s", err)
	}
}
