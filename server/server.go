package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/KernelPay/kube-google-iam/iam"
	"github.com/KernelPay/kube-google-iam/k8s"
	"github.com/KernelPay/kube-google-iam/mappings"
	"github.com/cenk/backoff"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"
)

const (
	defaultAppPort           = "8181"
	defaultCacheSyncAttempts = 10
	defaultServiceAccountKey = "cloud.google.com/service-account"
	defaultLogLevel          = "info"
	defaultMaxElapsedTime    = 2 * time.Second
	defaultMaxInterval       = 1 * time.Second
	defaultMetadataAddress   = "169.254.169.254"
	defaultHostIP            = "127.0.0.1"
	defaultNamespaceKey      = "cloud.google.com/allowed-service-accounts"
)

// Server encapsulates all of the parameters necessary for starting up
// the server. These can either be set via command line or directly.
type Server struct {
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
	AddIPTablesRule       bool
	Debug                 bool
	Insecure              bool
	NamespaceRestriction  bool
	Verbose               bool
	Version               bool
	k8s                   *k8s.Client
	iam                   *iam.Client
	serviceAccountMapper  *mappings.ServiceAccountMapper
	BackoffMaxElapsedTime time.Duration
	BackoffMaxInterval    time.Duration
}

type appHandler func(*log.Entry, http.ResponseWriter, *http.Request)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

// ServeHTTP implements the net/http server Handler interface
// and recovers from panics.
func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger := log.WithFields(log.Fields{
		"req.method": r.Method,
		"req.path":   r.URL.Path,
		"req.remote": parseRemoteAddr(r.RemoteAddr),
	})
	start := time.Now()
	defer func() {
		var err error
		if rec := recover(); rec != nil {
			switch t := rec.(type) {
			case string:
				err = errors.New(t)
			case error:
				err = t
			default:
				err = errors.New("Unknown error")
			}
			logger.WithField("res.status", http.StatusInternalServerError).
				Errorf("PANIC error processing request: %+v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}()
	rw := newResponseWriter(w)
	fn(logger, rw, r)
	if r.URL.Path != "/healthz" {
		latency := time.Since(start)
		logger.WithFields(log.Fields{"res.duration": latency.Nanoseconds(), "res.status": rw.statusCode}).
			Infof("%s %s (%d) took %d ns", r.Method, r.URL.Path, rw.statusCode, latency.Nanoseconds())
	}
}

func parseRemoteAddr(addr string) string {
	n := strings.IndexByte(addr, ':')
	if n <= 1 {
		return ""
	}
	hostname := addr[0:n]
	if net.ParseIP(hostname) == nil {
		return ""
	}
	return hostname
}

func (s *Server) getServiceAccountMapping(IP string) (*mappings.ServiceAccountMappingResult, error) {
	var serviceAccountMapping *mappings.ServiceAccountMappingResult
	var err error
	operation := func() error {
		serviceAccountMapping, err = s.serviceAccountMapper.GetServiceAccountMapping(IP)
		return err
	}

	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxInterval = s.BackoffMaxInterval
	expBackoff.MaxElapsedTime = s.BackoffMaxElapsedTime

	err = backoff.Retry(operation, expBackoff)
	if err != nil {
		return nil, err
	}

	return serviceAccountMapping, nil
}

// HealthResponse represents a response for the health check.
type HealthResponse struct {
	HostIP     string `json:"hostIP"`
	InstanceID string `json:"instanceId"`
}

func (s *Server) handleHealth(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(fmt.Sprintf("http://%s/latest/meta-data/instance-id", s.MetadataAddress))
	if err != nil {
		log.Errorf("Error getting instance id %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if resp.StatusCode != 200 {
		msg := fmt.Sprintf("Error getting instance id, got status: %+s", resp.Status)
		log.Error(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	instanceID, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error reading response body %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	health := &HealthResponse{InstanceID: string(instanceID), HostIP: s.HostIP}
	w.Header().Add("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(health); err != nil {
		log.Errorf("Error sending json %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleDebug(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	o, err := json.Marshal(s.serviceAccountMapper.DumpDebugInfo())
	if err != nil {
		log.Errorf("Error converting debug map to json: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	write(logger, w, string(o))
}

func (s *Server) handleDiscovery(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Metadata-Flavor", "Google")
	w.WriteHeader(200)
}

func (s *Server) extractServiceAccount(logger *log.Entry, w http.ResponseWriter, r *http.Request) *mappings.ServiceAccountMappingResult {
	w.Header().Set("Metadata-Flavor", "Google")

	if r.Header.Get("Metadata-Flavor") != "Google" {
		http.Error(w, "Missing Metadata-Flavor:Google header!", http.StatusForbidden)
		return nil
	}

	remoteIP := parseRemoteAddr(r.RemoteAddr)

	serviceAccountMapping, err := s.getServiceAccountMapping(remoteIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return nil
	}

	serviceAccountLogger := logger.WithFields(log.Fields{
		"pod.iam.serviceAccount": serviceAccountMapping.ServiceAccount,
		"ns.name":                serviceAccountMapping.Namespace,
	})

	wantedServiceAccount := mux.Vars(r)["serviceAccount"]

	if wantedServiceAccount != serviceAccountMapping.ServiceAccount && wantedServiceAccount != "default" {
		serviceAccountLogger.WithField("params.iam.serviceAccount", wantedServiceAccount).
			Error("Invalid serviceAccount: does not match annotated serviceAccount")
		http.Error(w, fmt.Sprintf("Invalid serviceAccount %s", wantedServiceAccount), http.StatusForbidden)
		return nil
	}

	return serviceAccountMapping
}

func (s *Server) handleToken(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	serviceAccountMapping := s.extractServiceAccount(logger, w, r)
	if serviceAccountMapping == nil {
		return
	}

	serviceAccountLogger := logger.WithFields(log.Fields{
		"pod.iam.serviceAccount": serviceAccountMapping.ServiceAccount,
		"ns.name":                serviceAccountMapping.Namespace,
	})

	credentials, err := s.iam.GetCredentials(serviceAccountMapping.ServiceAccount)
	if err != nil {
		serviceAccountLogger.Errorf("Error assuming serviceAccount %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	credentialsJSON := &struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}{
		AccessToken: credentials.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(credentials.Expires.Sub(time.Now()).Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(credentialsJSON); err != nil {
		serviceAccountLogger.Errorf("Error sending json %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleEmail(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	serviceAccountMapping := s.extractServiceAccount(logger, w, r)
	if serviceAccountMapping == nil {
		return
	}

	w.Write([]byte(serviceAccountMapping.ServiceAccount))
}

func (s *Server) handleServiceAccount(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	serviceAccountMapping := s.extractServiceAccount(logger, w, r)
	if serviceAccountMapping == nil {
		return
	}

	serviceAccountLogger := logger.WithFields(log.Fields{
		"pod.iam.serviceAccount": serviceAccountMapping.ServiceAccount,
		"ns.name":                serviceAccountMapping.Namespace,
	})

	// Here we assume the user has requested ?recursive=True
	result := &struct {
		Aliases []string `json:"aliases"`
		Email   string   `json:"email"`
		Scopes  []string `json:"scopes"`
	}{
		Aliases: []string{"default"},
		Email:   serviceAccountMapping.ServiceAccount,
		Scopes:  []string{"https://www.googleapis.com/auth/cloud-platform"},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		serviceAccountLogger.Errorf("Error sending json %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleServiceAccounts(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Metadata-Flavor", "Google")

	if r.Header.Get("Metadata-Flavor") != "Google" {
		http.Error(w, "Missing Metadata-Flavor:Google header!", http.StatusForbidden)
		return
	}

	remoteIP := parseRemoteAddr(r.RemoteAddr)

	serviceAccountMapping, err := s.getServiceAccountMapping(remoteIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Write([]byte(fmt.Sprintf("default/\n%s\n", serviceAccountMapping.ServiceAccount)))
}

// xForwardedForStripper is identical to http.DefaultTransport except that it
// strips X-Forwarded-For headers.  It fulfills the http.RoundTripper
// interface.
type xForwardedForStripper struct{}

// RoundTrip wraps the http.DefaultTransport.RoundTrip method, and strips
// X-Forwarded-For headers, since httputil.ReverseProxy.ServeHTTP adds it but
// the GCE metadata server rejects requests with that header.
func (x xForwardedForStripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Del("X-Forwarded-For")
	return http.DefaultTransport.RoundTrip(req)
}

func (s *Server) reverseProxyHandler(logger *log.Entry, w http.ResponseWriter, r *http.Request) {
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: s.MetadataAddress})
	proxy.Transport = xForwardedForStripper{}
	proxy.ServeHTTP(w, r)
	logger.WithField("metadata.url", s.MetadataAddress).Debug("Proxy ec2 metadata request")
}

func write(logger *log.Entry, w http.ResponseWriter, s string) {
	if _, err := w.Write([]byte(s)); err != nil {
		logger.Errorf("Error writing response: %+v", err)
	}
}

// Run runs the specified Server.
func (s *Server) Run() error {
	k, err := k8s.NewClient(s.KubernetesMaster, s.KubeconfigFile)
	if err != nil {
		return err
	}
	s.k8s = k
	s.serviceAccountMapper = mappings.NewServiceAccountMapper(
		s.ServiceAccountKey,
		s.DefaultServiceAccount,
		s.NamespaceRestriction,
		s.NamespaceKey,
		s.k8s,
	)
	podSynched := s.k8s.WatchForPods(k8s.NewPodHandler(s.ServiceAccountKey))
	namespaceSynched := s.k8s.WatchForNamespaces(k8s.NewNamespaceHandler(s.NamespaceKey))

	synced := false
	for i := 0; i < defaultCacheSyncAttempts && !synced; i++ {
		synced = cache.WaitForCacheSync(nil, podSynched, namespaceSynched)
	}

	if !synced {
		log.Fatalf("Attempted to wait for caches to be synced for %d however it is not done.  Giving up.", defaultCacheSyncAttempts)
	} else {
		log.Debugln("Caches have been synced.  Proceeding with server.")
	}

	r := mux.NewRouter()

	if s.Debug {
		// This is a potential security risk if enabled in some clusters, hence the flag
		r.Handle("/debug/store", appHandler(s.handleDebug))
	}
	r.Handle("/healthz", appHandler(s.handleHealth))
	r.Handle("/", appHandler(s.handleDiscovery))
	r.Handle("/computeMetadata/", appHandler(s.handleDiscovery))
	r.Handle("/computeMetadata/v1/", appHandler(s.handleDiscovery))
	r.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/token", appHandler(s.handleToken))
	r.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/email", appHandler(s.handleEmail))
	r.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/", appHandler(s.handleServiceAccount))
	r.Handle("/computeMetadata/v1/instance/service-accounts/", appHandler(s.handleServiceAccounts))
	r.Handle("/computeMetadata/v1/project/", appHandler(s.reverseProxyHandler))
	r.Handle("/computeMetadata/v1/project/project-id", appHandler(s.reverseProxyHandler))
	r.Handle("/computeMetadata/v1/project/numeric-project-id", appHandler(s.reverseProxyHandler))
	r.Handle("/computeMetadata/v1/instance/zone", appHandler(s.reverseProxyHandler))
	r.Handle("/computeMetadata/v1/instance/cpu-platform", appHandler(s.reverseProxyHandler))

	log.Infof("Listening on port %s", s.AppPort)
	if err := http.ListenAndServe(":"+s.AppPort, r); err != nil {
		log.Fatalf("Error creating http server: %+v", err)
	}
	return nil
}

// NewServer will create a new Server with default values.
func NewServer() *Server {
	return &Server{
		AppPort:               defaultAppPort,
		BackoffMaxElapsedTime: defaultMaxElapsedTime,
		ServiceAccountKey:     defaultServiceAccountKey,
		BackoffMaxInterval:    defaultMaxInterval,
		LogLevel:              defaultLogLevel,
		MetadataAddress:       defaultMetadataAddress,
		NamespaceKey:          defaultNamespaceKey,
		HostIP:                defaultHostIP,
	}
}
