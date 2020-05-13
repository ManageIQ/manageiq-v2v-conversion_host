package apis

import (
	"github.com/ManageIQ/manageiq-v2v-conversion_host/kubevirt-vmware/pkg/apis/v2v/v1alpha1"
)

func init() {
	// Register the types with the Scheme so the components can map objects to GroupVersionKinds and back
	AddToSchemes = append(AddToSchemes, v1alpha1.SchemeBuilder.AddToScheme)
}
