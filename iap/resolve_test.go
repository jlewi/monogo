package iap

import (
	"testing"

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
