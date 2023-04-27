package v1alpha1

// IAPAppPolicy is modeled on IAMPolicy
// https://cloud.google.com/config-connector/docs/reference/resource-docs/iam/iampolicy
// It is used to set permissions on IAP web app resources.
type IAPAppPolicy struct {
	Kind string `yaml:"kind" json:"kind"`
	Spec Policy `yaml:"spec" json:"spec"`
}

type Policy struct {
	ResourceRef ResourceRef `yaml:"resourceRef" json:"resourceRef"`
	Bindings    []Binding   `yaml:"bindings" json:"bindings"`
}

type ResourceRef struct {
	// External should be the name of the backend in a format like
	// "projects/{project NUMBER or ID}/iap_web/compute/services/{backend service name or id}
	External string `yaml:"external" json:"external"`

	// ServiceRef references a K8s service from which the backend will be computed
	ServiceRef *ServiceRef `yaml:"serviceRef" json:"serviceRef"`
}

type ServiceRef struct {
	Project string `yaml:"project" json:"project"`
	Service string `yaml:"service" json:"service"`
	// Ingress isn't needed if you are using a gateway
	// TODO(jeremy): Can we deprecate specifying ingress and instead get the neg name from the K8s service annotation
	// always i.e always use resolver.GetGCPBackendFromService
	Ingress   string `yaml:"ingress" json:"ingress"`
	Namespace string `yaml:"namespace" json:"namespace"`
}

type Binding struct {
	Role    string   `yaml:"role" json:"role"`
	Members []string `yaml:"members" json:"members"`
}

// IsValid checks whether the policy is valid
func (p *IAPAppPolicy) IsValid() (bool, string) {
	externalSet := p.Spec.ResourceRef.External != ""
	serviceSet := p.Spec.ResourceRef.ServiceRef != nil
	if externalSet == serviceSet {
		return false, "Exactly one of External and ServiceRef must be set"
	}
	return true, ""
}
