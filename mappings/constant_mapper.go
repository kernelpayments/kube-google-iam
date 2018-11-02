package mappings

type ConstantMapper struct {
	serviceAccount string
}

func (m *ConstantMapper) GetServiceAccountMapping(IP string) (*Result, error) {
	return &Result{
		ServiceAccount: m.serviceAccount,
		IP:             IP,
		Namespace:      "default",
	}, nil
}

func NewConstantMapper(serviceAccount string) *ConstantMapper {
	return &ConstantMapper{
		serviceAccount: serviceAccount,
	}
}
