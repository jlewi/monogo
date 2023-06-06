package iap

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jlewi/monogo/helpers"

	"github.com/google/go-cmp/cmp"
	"github.com/jlewi/monogo/k8s"
	"k8s.io/client-go/util/homedir"

	compute "cloud.google.com/go/compute/apiv1"
	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_GetGCPBackendFromIngress(t *testing.T) {
	type testCase struct {
		Annotation  string
		ServiceName string
		Namespace   string
		Expected    string
	}

	cases := []testCase{
		{
			Annotation:  "{\"k8s1-9202d8d9-healthapp-server-8080-f62d8d54\":\"HEALTHY\"}",
			Namespace:   "healthapp",
			ServiceName: "server",
			Expected:    "k8s1-9202d8d9-healthapp-server-8080-f62d8d54",
		},
		{
			Annotation:  "{\"k8s1-9202d8d9-healthapp-server-8080-f62d8d54\":\"HEALTHY\", \"k8s1-9202d8d9-healthapp-server2-8080-f62d8d54\":\"HEALTHY\"}",
			Namespace:   "healthapp",
			ServiceName: "server",
			Expected:    "k8s1-9202d8d9-healthapp-server-8080-f62d8d54",
		},
	}

	for _, c := range cases {
		t.Run(c.ServiceName, func(t *testing.T) {
			ingress := &v1.Ingress{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						backendsAnnotation: c.Annotation,
					},
				},
				Spec:   v1.IngressSpec{},
				Status: v1.IngressStatus{},
			}
			actual, err := GetGCPBackendFromIngress(ingress, c.Namespace, c.ServiceName)
			if err != nil {
				t.Fatalf("Failed with error: %v", err)
			}
			if actual != c.Expected {
				t.Errorf("Got %v; want %v", actual, c.Expected)
			}
		})
	}
}

func Test_GatewayToBackend(t *testing.T) {
	// This is an "integration" test that requires access to GCP
	// It is useful for development. The actual values would have to be updated
	// based on the project and service used for testing.
	if os.Getenv("GITHUB_ACTIONS") != "" {
		t.Skip("Skipping test in GitHub Actions")
	}
	bSvc, err := compute.NewBackendServicesRESTClient(context.Background())
	helpers.DeferIgnoreError(bSvc.Close)

	if err != nil {
		t.Fatalf("Failed to create backend service client: %v", err)
	}

	k8sFlags := &k8s.K8SClientFlags{
		Kubeconfig: filepath.Join(homedir.HomeDir(), ".kube", "config"),
	}
	k8sClient, err := k8sFlags.NewClient()

	if err != nil {
		t.Fatalf("Failed to create k8s client: %v", err)
	}

	negToBackend, err := GetGCPBackendFromService(k8sClient, bSvc, "chat-lewi", "gateway", "site-v1")
	if err != nil {
		t.Fatalf("Failed to get backend: %v", err)
	}

	expected := map[string]string{
		"k8s1-ec8d20c1-gateway-site-v1-8080-c416a331": "gkegw1-u3ex-gateway-site-v1-8080-r546wxld07pe",
	}

	if d := cmp.Diff(expected, negToBackend); d != "" {
		t.Errorf("Got unexpected diff: %v", d)
	}
}
