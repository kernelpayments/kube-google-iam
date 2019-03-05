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

	"github.com/cenk/backoff"
	"github.com/gorilla/mux"
	"github.com/kernelpayments/kube-google-iam/iam"
	"github.com/kernelpayments/kube-google-iam/k8s"
	"github.com/kernelpayments/kube-google-iam/mappings"
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

var metadataHeader = &http.Header{
	"Metadata-Flavor": []string{"Google"},
}

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
	AttributeWhitelist    []string
	AttributeWhitelistSet map[string]struct{}
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

func (s *Server) queryMetadata(path string) ([]byte, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s%s", s.MetadataAddress, path), nil)
	if err != nil {
		return nil, fmt.Errorf("query metadata %s: new request %+v", path, err)
	}
	req.Header = *metadataHeader
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query metadata %s: %+v", path, err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("query metadata %s: got status %+s", path, resp.Status)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("query metadata %s: can't read response body: %+v", path, err)
	}
	return body, nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	instanceID, err := s.queryMetadata("/computeMetadata/v1/instance/id")
	if err != nil {
		log.Errorf("Error getting instance id: %+v", err)
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

	credentials, err := s.iam.GetAccessToken(serviceAccountMapping.ServiceAccount)
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
		AccessToken: credentials.Token,
		TokenType:   "Bearer",
		ExpiresIn:   int64(credentials.Expires.Sub(time.Now()).Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(credentialsJSON); err != nil {
		serviceAccountLogger.Errorf("Error sending json %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleIdentity(w http.ResponseWriter, r *http.Request) {
	serviceAccountMapping := s.extractServiceAccount(w, r)
	if serviceAccountMapping == nil {
		return
	}

	logger := LoggerFromContext(r.Context())
	serviceAccountLogger := logger.WithFields(log.Fields{
		"pod.iam.serviceAccount": serviceAccountMapping.ServiceAccount,
		"ns.name":                serviceAccountMapping.Namespace,
	})

	audience := r.URL.Query().Get("audience")
	if audience == "" {
		http.Error(w, "audience parameter required", http.StatusBadRequest)
		return
	}

	credentials, err := s.iam.GetIDToken(serviceAccountMapping.ServiceAccount, audience)
	if err != nil {
		serviceAccountLogger.Errorf("Error assuming serviceAccount %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte(credentials.Token))
}

func (s *Server) handleEmail(w http.ResponseWriter, r *http.Request) {
	serviceAccountMapping := s.extractServiceAccount(w, r)
	if serviceAccountMapping == nil {
		return
	}

	w.Write([]byte(serviceAccountMapping.ServiceAccount))
}

func (s *Server) handleScopes(w http.ResponseWriter, r *http.Request) {
	serviceAccountMapping := s.extractServiceAccount(w, r)
	if serviceAccountMapping == nil {
		return
	}

	// Hardcode the scopes. Not sure if there's a way to dynamically query them?
	// This is needed by gsutil.
	w.Write([]byte("https://www.googleapis.com/auth/cloud-platform\nhttps://www.googleapis.com/auth/userinfo.email\n"))
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

func (s *Server) handleSlashRedir(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Metadata-Flavor", "Google")

	if r.Header.Get("Metadata-Flavor") != "Google" {
		http.Error(w, "Missing Metadata-Flavor:Google header!", http.StatusForbidden)
		return
	}

	http.Redirect(w, r, "http://metadata.google.internal"+r.URL.Path+"/", http.StatusMovedPermanently)
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

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: s.MetadataAddress})
	proxy.Transport = xForwardedForStripper{}
	proxy.ServeHTTP(w, r)
	logger := LoggerFromContext(r.Context())
	logger.WithField("metadata.url", s.MetadataAddress).Debug("Proxy ec2 metadata request")
}

func (s *Server) handleAttributes(w http.ResponseWriter, r *http.Request) {
	logger := LoggerFromContext(r.Context())

	attributesJSON, err := s.queryMetadata("/computeMetadata/v1/instance/attributes/?recursive=true")
	if err != nil {
		logger.Errorf("Error getting attributes: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var attributes map[string]string
	err = json.Unmarshal(attributesJSON, &attributes)
	if err != nil {
		logger.Errorf("Error unmarshaling attributes: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result := make(map[string]string)
	for k, v := range attributes {
		if _, ok := s.AttributeWhitelistSet[k]; ok {
			result[k] = v
		}
	}

	if strings.ToLower(r.URL.Query().Get("recursive")) == "true" {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			logger.Errorf("Error sending json %+v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	} else {
		var data []byte
		for k := range result {
			data = append(data, []byte(k)...)
			data = append(data, '\n')
		}
		w.Header().Set("Content-Type", "application/text")
		if _, err := w.Write(data); err != nil {
			logger.Errorf("Error sending response %+v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (s *Server) handleAttribute(w http.ResponseWriter, r *http.Request) {
	logger := LoggerFromContext(r.Context())

	attribute := mux.Vars(r)["attribute"]

	if _, ok := s.AttributeWhitelistSet[attribute]; !ok {
		http.Error(w, "404 not found", http.StatusNotFound)
		return
	}

	value, err := s.queryMetadata("/computeMetadata/v1/instance/attributes/" + attribute)
	if err != nil {
		logger.Errorf("Error getting attribute: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/text")
	if _, err := w.Write(value); err != nil {
		logger.Errorf("Error sending response %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func write(logger *log.Entry, w http.ResponseWriter, s string) {
	if _, err := w.Write([]byte(s)); err != nil {
		logger.Errorf("Error writing response: %+v", err)
	}
}

// Run runs the specified Server.
func (s *Server) Run() error {
	s.AttributeWhitelistSet = make(map[string]struct{})
	for _, a := range s.AttributeWhitelist {
		s.AttributeWhitelistSet[a] = struct{}{}
	}

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
	r.HandleFunc("/computeMetadata", s.handleSlashRedir)
	r.HandleFunc("/computeMetadata/", s.handleDiscovery)
	r.HandleFunc("/computeMetadata/v1/", s.handleSlashRedir)
	r.HandleFunc("/computeMetadata/v1/", s.handleDiscovery)
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts", s.handleSlashRedir)
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/", s.handleServiceAccounts)
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}", s.handleSlashRedir)
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/", s.handleServiceAccount)
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/token", s.handleToken)
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/email", s.handleEmail)
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/identity", s.handleIdentity)
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/scopes", s.handleScopes)
	r.HandleFunc("/computeMetadata/v1/project", s.handleSlashRedir)
	r.HandleFunc("/computeMetadata/v1/project/", s.handleProxy)
	r.HandleFunc("/computeMetadata/v1/project/project-id", s.handleProxy)
	r.HandleFunc("/computeMetadata/v1/project/numeric-project-id", s.handleProxy)
	r.HandleFunc("/computeMetadata/v1/instance", s.handleSlashRedir)
	r.HandleFunc("/computeMetadata/v1/instance/", s.handleDiscovery)
	r.HandleFunc("/computeMetadata/v1/instance/id", s.handleProxy)
	r.HandleFunc("/computeMetadata/v1/instance/zone", s.handleProxy)
	r.HandleFunc("/computeMetadata/v1/instance/cpu-platform", s.handleProxy)
	r.HandleFunc("/computeMetadata/v1/instance/attributes", s.handleSlashRedir)
	r.HandleFunc("/computeMetadata/v1/instance/attributes/", s.handleAttributes)
	r.HandleFunc("/computeMetadata/v1/instance/attributes/{attribute:[^/]+}", s.handleAttribute)

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
