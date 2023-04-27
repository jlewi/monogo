package k8s

import (
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type K8SClientFlags struct {
	Kubeconfig string
}

func (f *K8SClientFlags) AddFlags(cmd *cobra.Command) {
	kubeconfig := ""
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	cmd.Flags().StringVarP(&f.Kubeconfig, "kubeconfig", "", kubeconfig, "The kubeconfig file to use")
}

func (f *K8SClientFlags) NewClient() (*kubernetes.Clientset, error) {
	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", f.Kubeconfig)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to build config from file %v", f.Kubeconfig)
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create clientset")
	}
	return clientset, nil
}
