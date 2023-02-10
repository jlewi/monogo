package iap

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	backendsAnnotation = "ingress.kubernetes.io/backends"
)

// GetGCPBackend determines the GCP backend associated with the given K8s service.
// The backends are stored as annotations on the K8s ingress. An ingress can have multiple backends but these
// should be named off of the service.
func GetGCPBackend(client *kubernetes.Clientset, namespace string, serviceName string, ingressName string) (string, error) {
	ingress, err := client.NetworkingV1().Ingresses(namespace).Get(context.Background(), ingressName, metav1.GetOptions{})
	if err != nil {
		return "", errors.Wrapf(err, "Failed to get ingress: %v.%v", namespace, ingressName)
	}

	return GetGCPBackendFromIngress(ingress, namespace, serviceName)
}

// GetGCPBackendFromIngress determines the GCP backend associated with the given K8s service.
// The backends are stored as annotations on the K8s ingress. An ingress can have multiple backends but these
// should be named off of the service.
func GetGCPBackendFromIngress(ingress *v1.Ingress, namespace string, serviceName string) (string, error) {

	backendsJSON, ok := ingress.Annotations[backendsAnnotation]
	if !ok {
		return "", fmt.Errorf("Ingress %v.%v is missing annotation %v", namespace, ingress.Name, backendsAnnotation)
	}

	backends := make(map[string]string)
	if err := json.Unmarshal([]byte(backendsJSON), &backends); err != nil {
		return "", errors.Wrapf(err, "Could not unmarshal %v to map[string]string", backendsJSON)
	}
	re, err := regexp.Compile(fmt.Sprintf(".*-%v-%v-.*", namespace, serviceName))
	if err != nil {
		return "", errors.Wrapf(err, "Failed to compile regex to match service name")
	}

	matches := []string{}
	for k := range backends {
		if re.MatchString(k) {
			matches = append(matches, k)
		}
	}

	if len(matches) > 1 {
		return "", errors.Errorf("Multiple backends matched for service %v.%v; %v", namespace, serviceName, strings.Join(matches, ","))
	}

	if len(matches) == 0 {
		return "", errors.Errorf("No backends matched for service %v.%v; %v", namespace, serviceName, backendsJSON)
	}

	return matches[0], nil
}

// BackendIAPName returns the full IAP resource name for the backend
func BackendIAPName(project string, backend string) string {
	return fmt.Sprintf("projects/%v/iap_web/compute/services/%v", project, backend)
}
