package mappings

type Mapper interface {
	GetServiceAccountMapping(IP string) (*Result, error)
}
type MapperDebug interface {
	DumpDebugInfo() map[string]interface{}
}

// Result represents the relevant information for a given mapping request
type Result struct {
	ServiceAccount string
	IP             string
	Namespace      string
}
