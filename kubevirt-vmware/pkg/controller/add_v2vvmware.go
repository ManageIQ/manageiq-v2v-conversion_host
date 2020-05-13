package controller

import (
	gc "github.com/ManageIQ/manageiq-v2v-conversion_host/kubevirt-vmware/pkg/controller/garbage_collector"
	"github.com/ManageIQ/manageiq-v2v-conversion_host/kubevirt-vmware/pkg/controller/gcovirtprovider"
	"github.com/ManageIQ/manageiq-v2v-conversion_host/kubevirt-vmware/pkg/controller/ovirtprovider"
	"github.com/ManageIQ/manageiq-v2v-conversion_host/kubevirt-vmware/pkg/controller/v2vvmware"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, v2vvmware.Add)
	AddToManagerFuncs = append(AddToManagerFuncs, ovirtprovider.Add)
	AddToManagerFuncs = append(AddToManagerFuncs, gc.GC)
	AddToManagerFuncs = append(AddToManagerFuncs, gcovirtprovider.ProviderGC)
}
