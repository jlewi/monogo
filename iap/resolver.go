package iap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"google.golang.org/api/iterator"

	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"github.com/pkg/errors"
	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	backendsAnnotation = "ingress.kubernetes.io/backends"
	negAnnotation      = "cloud.google.com/neg-status"
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

type NegStatus struct {
	NetworkEndpointGroups map[string]string `json:"network_endpoint_groups"`
	Zones                 []string          `json:"zones"`
}

// GetGCPBackendFromService determines the GCP backend associated with the given K8s service.
// It fetches the Neg associated with the given K8s service from its annotations.
// It then loops over backendservices to find the backend associated with that neg.
//
// Returns a mapping from neg name to backend service name.
//
// There can be more than 1 neg associated with a backend service; because negs are port specific
// N.B. This was tested with the Gateway resource but it should work with the Ingress resource as well.
// It builds a mapping from BackendServices to Negs.
func GetGCPBackendFromService(client *kubernetes.Clientset, bkSvc *compute.BackendServicesClient, project string, namespace string, serviceName string) (map[string]string, error) {
	log := zapr.NewLogger(zap.L())
	if serviceName == "" {
		return nil, errors.Errorf("service name cannot be empty")
	}
	if namespace == "" {
		return nil, errors.Errorf("namespace cannot be empty")
	}
	negToBackend := make(map[string]string)
	k8sSvc, err := client.CoreV1().Services(namespace).Get(context.Background(), serviceName, metav1.GetOptions{})
	if err != nil {
		return negToBackend, errors.Wrapf(err, "Failed to get service: %v.%v", namespace, serviceName)
	}

	negStatus, ok := k8sSvc.Annotations[negAnnotation]
	if !ok {
		return negToBackend, fmt.Errorf("Service %v.%v is missing annotation %v", namespace, k8sSvc.Name, negAnnotation)
	}

	neg := NegStatus{}
	if err := json.Unmarshal([]byte(negStatus), &neg); err != nil {
		return negToBackend, errors.Wrapf(err, "Could not unmarshal %v to NegStatus", negStatus)
	}

	for _, negName := range neg.NetworkEndpointGroups {
		negToBackend[negName] = ""
	}

	bSvc, err := compute.NewBackendServicesRESTClient(context.Background())
	defer bSvc.Close()

	if err != nil {
		return negToBackend, errors.Wrapf(err, "Failed to create backend service client")
	}

	req := &computepb.ListBackendServicesRequest{
		Project: project,
	}

	iter := bSvc.List(context.Background(), req)

	for svc, listErr := iter.Next(); listErr != iterator.Done; svc, listErr = iter.Next() {
		if listErr != nil {
			return negToBackend, listErr
		}

		log.Info("Found backend service", "name", *svc.Name, "num_backends", len(svc.Backends))

		for _, b := range svc.Backends {
			u, err := url.Parse(*b.Group)
			if err != nil {
				return negToBackend, errors.Wrapf(err, "Failed to parse backend group url %v", *b.Group)
			}
			segments := strings.Split(u.Path, "/")
			if segments[len(segments)-2] != "networkEndpointGroups" {
				continue
			}

			negName := segments[len(segments)-1]
			if v, ok := negToBackend[negName]; ok {
				if v != "" {
					return negToBackend, fmt.Errorf("Found multiple backends for neg %v", negName)
				}
				negToBackend[negName] = *svc.Name
			}
		}
	}

	return negToBackend, nil
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
