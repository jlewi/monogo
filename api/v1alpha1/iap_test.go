package v1alpha1

import (
	"os"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
)

func Test_iap(t *testing.T) {
	// Test unmarshalling the JSON version of the proto
	type testCase struct {
		Name     string
		Expected *IAPAppPolicy
	}

	cases := []testCase{
		{
			Name: "iap_policy.yaml",
			Expected: &IAPAppPolicy{
				Kind: "IAPAppPolicy",
				Spec: Policy{
					ResourceRef: ResourceRef{
						External: "projects/dev-foo/iap_web/compute/services/k8s1-9202d8d9-healthapp-server-8080-f62d8d54",
					},
					Bindings: []Binding{
						{
							Role: "roles/iap.httpsResourceAccessor",
							Members: []string{
								"group:gcp-developers@fooai.com",
							},
						},
					},
				},
			},
		},
		{
			Name: "iap_policy_service_ref.yaml",
			Expected: &IAPAppPolicy{
				Kind: "IAPAppPolicy",
				Spec: Policy{
					ResourceRef: ResourceRef{
						ServiceRef: &ServiceRef{
							Project:   "dev-foo",
							Service:   "argocd-server",
							Ingress:   "argocd",
							Namespace: "argocd",
						},
					},
					Bindings: []Binding{
						{
							Role: "roles/iap.httpsResourceAccessor",
							Members: []string{
								"group:gcp-developers@fooai.com",
							},
						},
					},
				},
			},
		},
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory; %v", err)
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			path := path.Join(cwd, "test_data", c.Name)

			b, err := os.Open(path)
			if err != nil {
				t.Fatalf("Failed to read file: %v; error %v", path, err)
			}

			d := yaml.NewDecoder(b)

			actual := &IAPAppPolicy{}
			if err := d.Decode(actual); err != nil {
				t.Fatalf("Failed to decode the IAPAppPolicy; %v", err)
			}

			if diff := cmp.Diff(c.Expected, actual); diff != "" {
				t.Fatalf("Unexpected diff:\n%v", diff)
			}
		})
	}
}
