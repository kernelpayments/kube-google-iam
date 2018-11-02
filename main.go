package main

import (
	"github.com/KernelPay/kube-google-iam/config"
	"github.com/KernelPay/kube-google-iam/iam"
	"github.com/KernelPay/kube-google-iam/iptables"
	"github.com/KernelPay/kube-google-iam/k8s"
	"github.com/KernelPay/kube-google-iam/mappings"
	"github.com/KernelPay/kube-google-iam/server"
	"github.com/KernelPay/kube-google-iam/version"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"
)

const (
	cacheSyncAttempts = 10
)

func main() {

	cfg := config.Load()
	if cfg.Version {
		version.PrintVersionAndExit()
	}

	logLevel, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Fatalf("%s", err)
	}

	if cfg.Verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(logLevel)
	}

	var mapper mappings.Mapper
	if cfg.MockServiceAccount == "" {
		k8sClient, err := k8s.NewClient(cfg.KubernetesMaster, cfg.KubeconfigFile)
		if err != nil {
			log.Fatal(err)
		}

		mapper = mappings.NewK8sMapper(
			cfg.ServiceAccountKey,
			cfg.DefaultServiceAccount,
			cfg.NamespaceRestriction,
			cfg.NamespaceKey,
			k8sClient,
		)
		podSynched := k8sClient.WatchForPods(k8s.NewPodHandler(cfg.ServiceAccountKey))
		namespaceSynched := k8sClient.WatchForNamespaces(k8s.NewNamespaceHandler(cfg.NamespaceKey))
		synced := false
		for i := 0; i < cacheSyncAttempts && !synced; i++ {
			synced = cache.WaitForCacheSync(nil, podSynched, namespaceSynched)
		}

		if !synced {
			log.Fatalf("Attempted to wait for caches to be synced for %d however it is not done.  Giving up.", cacheSyncAttempts)
		} else {
			log.Debugln("Caches have been synced.  Proceeding with server.")
		}
	} else {
		mapper = mappings.NewConstantMapper(cfg.MockServiceAccount)
	}
	iam := iam.NewClient()

	s := server.NewServer(cfg, iam, mapper)

	if cfg.AddIPTablesRule {
		if err := iptables.AddRule(cfg.AppPort, cfg.MetadataAddress, cfg.HostInterface, cfg.HostIP); err != nil {
			log.Fatalf("%s", err)
		}
	}

	if err := s.Run(); err != nil {
		log.Fatalf("%s", err)
	}
}
