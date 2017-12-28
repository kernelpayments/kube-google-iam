package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime"
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

type logHandler struct {
	handler http.Handler
}

func newLogHandler(handler http.Handler) *logHandler {
	return &logHandler{
		handler: handler,
	}
}

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
func (h logHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger := log.WithFields(log.Fields{
		"req.method": r.Method,
		"req.path":   r.URL.Path,
		"req.remote": parseRemoteAddr(r.RemoteAddr),
	})
	start := time.Now()
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			logger.WithField("res.status", http.StatusInternalServerError).
				Errorf("PANIC serving request: %v\n%s", err, buf)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		}
	}()
	rw := newResponseWriter(w)
	h.handler.ServeHTTP(rw, r.WithContext(ContextWithLogger(r.Context(), logger)))
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

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleDebug(w http.ResponseWriter, r *http.Request) {
	o, err := json.Marshal(s.serviceAccountMapper.DumpDebugInfo())
	if err != nil {
		log.Errorf("Error converting debug map to json: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	logger := LoggerFromContext(r.Context())
	write(logger, w, string(o))
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Metadata-Flavor", "Google")
	w.WriteHeader(200)
}

func (s *Server) extractServiceAccount(w http.ResponseWriter, r *http.Request) *mappings.ServiceAccountMappingResult {
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

	logger := LoggerFromContext(r.Context())
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

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	serviceAccountMapping := s.extractServiceAccount(w, r)
	if serviceAccountMapping == nil {
		return
	}

	logger := LoggerFromContext(r.Context())
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

func (s *Server) handleEmail(w http.ResponseWriter, r *http.Request) {
	serviceAccountMapping := s.extractServiceAccount(w, r)
	if serviceAccountMapping == nil {
		return
	}

	w.Write([]byte(serviceAccountMapping.ServiceAccount))
}

func (s *Server) handleServiceAccount(w http.ResponseWriter, r *http.Request) {
	serviceAccountMapping := s.extractServiceAccount(w, r)
	if serviceAccountMapping == nil {
		return
	}

	logger := LoggerFromContext(r.Context())
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

func (s *Server) handleServiceAccounts(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) reverseProxyHandler(w http.ResponseWriter, r *http.Request) {
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: s.MetadataAddress})
	proxy.Transport = xForwardedForStripper{}
	proxy.ServeHTTP(w, r)
	logger := LoggerFromContext(r.Context())
	logger.WithField("metadata.url", s.MetadataAddress).Debug("Proxy ec2 metadata request")
}

func write(logger *log.Entry, w http.ResponseWriter, s string) {
	if _, err := w.Write([]byte(s)); err != nil {
		logger.Errorf("Error writing response: %+v", err)
	}
}

// Run runs the specified Server.
func (s *Server) Run() error {
	s.iam = iam.NewClient()

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
		r.HandleFunc("/debug/store", s.handleDebug)
	}
	r.HandleFunc("/healthz", s.handleHealth)
	r.HandleFunc("/", s.handleDiscovery)
	r.HandleFunc("/computeMetadata/", s.handleDiscovery)
	r.HandleFunc("/computeMetadata/v1/", s.handleDiscovery)
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/token", s.handleToken)
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/email", s.handleEmail)
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/", s.handleServiceAccount)
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/", s.handleServiceAccounts)
	r.HandleFunc("/computeMetadata/v1/project/", s.reverseProxyHandler)
	r.HandleFunc("/computeMetadata/v1/project/project-id", s.reverseProxyHandler)
	r.HandleFunc("/computeMetadata/v1/project/numeric-project-id", s.reverseProxyHandler)
	r.HandleFunc("/computeMetadata/v1/instance/zone", s.reverseProxyHandler)
	r.HandleFunc("/computeMetadata/v1/instance/cpu-platform", s.reverseProxyHandler)

	log.Infof("Listening on port %s", s.AppPort)
	if err := http.ListenAndServe(":"+s.AppPort, newLogHandler(r)); err != nil {
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
