package mappings

import (
	"fmt"

	"github.com/kernelpayments/kube-google-iam/k8s"
	glob "github.com/ryanuber/go-glob"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

// ServiceAccountMapper handles relevant logic around associating IPs with a given IAM serviceAccount
type ServiceAccountMapper struct {
	defaultServiceAccount string
	iamServiceAccountKey  string
	namespaceKey          string
	namespaceRestriction  bool
	store                 store
}

type store interface {
	ListPodIPs() []string
	PodByIP(string) (*v1.Pod, error)
	ListNamespaces() []string
	NamespaceByName(string) (*v1.Namespace, error)
}

// ServiceAccountMappingResult represents the relevant information for a given mapping request
type ServiceAccountMappingResult struct {
	ServiceAccount string
	IP             string
	Namespace      string
}

// GetServiceAccountMapping returns the normalized iam ServiceAccountMappingResult based on IP address
func (r *ServiceAccountMapper) GetServiceAccountMapping(IP string) (*ServiceAccountMappingResult, error) {
	pod, err := r.store.PodByIP(IP)
	// If attempting to get a Pod that maps to multiple IPs
	if err != nil {
		return nil, err
	}

	serviceAccount, err := r.extractServiceAccount(pod)
	if err != nil {
		return nil, err
	}

	// Determine if serviceAccount is allowed to be used in pod's namespace
	if r.checkServiceAccountForNamespace(serviceAccount, pod.GetNamespace()) {
		return &ServiceAccountMappingResult{ServiceAccount: serviceAccount, Namespace: pod.GetNamespace(), IP: IP}, nil
	}

	return nil, fmt.Errorf("ServiceAccount requested %s not valid for namespace of pod at %s with namespace %s", serviceAccount, IP, pod.GetNamespace())
}

// extractServiceAccount extracts the serviceAccount to be used for a given pod,
// taking into consideration the appropriate fallback logic and defaulting
// logic along with the namespace serviceAccount restrictions
func (r *ServiceAccountMapper) extractServiceAccount(pod *v1.Pod) (string, error) {
	serviceAccount, annotationPresent := pod.GetAnnotations()[r.iamServiceAccountKey]

	if !annotationPresent && r.defaultServiceAccount == "" {
		return "", fmt.Errorf("Unable to find serviceAccount for IP %s", pod.Status.PodIP)
	}

	if !annotationPresent {
		log.Warnf("Using fallback serviceAccount for IP %s", pod.Status.PodIP)
		serviceAccount = r.defaultServiceAccount
	}

	return serviceAccount, nil
}

// checkServiceAccountForNamespace checks the 'database' for a serviceAccount allowed in a namespace,
// returns true if the serviceAccount is found, otheriwse false
func (r *ServiceAccountMapper) checkServiceAccountForNamespace(serviceAccountArn string, namespace string) bool {
	if !r.namespaceRestriction || serviceAccountArn == r.defaultServiceAccount {
		return true
	}

	ns, err := r.store.NamespaceByName(namespace)
	if err != nil {
		log.Debugf("Unable to find an indexed namespace of %s", namespace)
		return false
	}

	ar := k8s.GetNamespaceServiceAccountAnnotation(ns, r.namespaceKey)
	for _, serviceAccountPattern := range ar {
		if glob.Glob(serviceAccountPattern, serviceAccountArn) {
			log.Debugf("ServiceAccount: %s matched %s on namespace:%s.", serviceAccountArn, serviceAccountPattern, namespace)
			return true
		}
	}
	log.Warnf("ServiceAccount: %s on namespace: %s not found.", serviceAccountArn, namespace)
	return false
}

// DumpDebugInfo outputs all the serviceAccounts by IP address.
func (r *ServiceAccountMapper) DumpDebugInfo() map[string]interface{} {
	output := make(map[string]interface{})
	serviceAccountsByIP := make(map[string]string)
	namespacesByIP := make(map[string]string)
	serviceAccountsByNamespace := make(map[string][]string)

	for _, ip := range r.store.ListPodIPs() {
		// When pods have `hostNetwork: true` they share an IP and we receive an error
		if pod, err := r.store.PodByIP(ip); err == nil {
			namespacesByIP[ip] = pod.Namespace
			if serviceAccount, ok := pod.GetAnnotations()[r.iamServiceAccountKey]; ok {
				serviceAccountsByIP[ip] = serviceAccount
			} else {
				serviceAccountsByIP[ip] = ""
			}
		}
	}

	for _, namespaceName := range r.store.ListNamespaces() {
		if namespace, err := r.store.NamespaceByName(namespaceName); err == nil {
			serviceAccountsByNamespace[namespace.GetName()] = k8s.GetNamespaceServiceAccountAnnotation(namespace, r.namespaceKey)
		}
	}

	output["serviceAccountsByIP"] = serviceAccountsByIP
	output["namespaceByIP"] = namespacesByIP
	output["serviceAccountsByNamespace"] = serviceAccountsByNamespace
	return output
}

// NewServiceAccountMapper returns a new ServiceAccountMapper for use.
func NewServiceAccountMapper(serviceAccountKey string, defaultServiceAccount string, namespaceRestriction bool, namespaceKey string, kubeStore store) *ServiceAccountMapper {
	return &ServiceAccountMapper{
		defaultServiceAccount: defaultServiceAccount,
		iamServiceAccountKey:  serviceAccountKey,
		namespaceKey:          namespaceKey,
		namespaceRestriction:  namespaceRestriction,
		store:                 kubeStore,
	}
}
