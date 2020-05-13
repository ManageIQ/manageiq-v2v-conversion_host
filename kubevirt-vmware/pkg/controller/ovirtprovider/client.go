package ovirtprovider

import (
	"context"
	"encoding/json"
	"fmt"

	ovirtsdk "github.com/ovirt/go-ovirt"
	kubevirtv1alpha1 "github.com/ManageIQ/manageiq-v2v-conversion_host/kubevirt-vmware/pkg/apis/v2v/v1alpha1"
	v2vv1alpha1 "github.com/ManageIQ/manageiq-v2v-conversion_host/kubevirt-vmware/pkg/apis/v2v/v1alpha1"
)

// Client struct holding implementation details required to interact with oVirt engine
type Client struct {
	conn *ovirtsdk.Connection
	ctx  context.Context
}

// VM holds name and cluster name which uniqualy identifies a vm
type VM struct {
	Name    string
	Cluster string
}

// NewClient creates new client struct based on connection details provided
func NewClient(ctx context.Context, url string, username string, password string, ca string) (*Client, error) {
	conn, err := ovirtsdk.NewConnectionBuilder().
		URL(url).
		Username(username).
		Password(password).
		CACert([]byte(ca)).
		Build()
	if err != nil {
		return nil, err
	}

	c := &Client{
		conn: conn,
		ctx:  ctx,
	}
	return c, nil
}

// Close makes sure that connection is closed
func (c *Client) Close() {
	c.conn.Close()
}

// GetVMs returns a list of vms from oVirt
func (c *Client) GetVMs() (map[string]VM, error) {
	vmsService := c.conn.SystemService().VmsService()
	vmsResponse, err := vmsService.List().Send()
	if err != nil {
		return nil, err
	}

	vmMap := make(map[string]VM)
	clusterMap, err := c.getClusters()
	if err != nil {
		return nil, err
	}
	if vms, ok := vmsResponse.Vms(); ok {
		for _, vm := range vms.Slice() {
			if vmName, ok := vm.Name(); ok {
				if vmID, ok := vm.Id(); ok {
					if cluster, ok := vm.Cluster(); ok {
						if cherf, ok := cluster.Href(); ok {
							vmMap[vmID] = VM{Name: vmName, Cluster: clusterMap[cherf]}
						}
					}
				}
			}
		}
	}
	return vmMap, nil
}

func (c *Client) getClusters() (map[string]string, error) {
	clusterMap := make(map[string]string)
	clustersResponse, err := c.conn.SystemService().ClustersService().List().Send()
	if err != nil {
		return nil, err
	}
	if clusters, ok := clustersResponse.Clusters(); ok {
		for _, cluster := range clusters.Slice() {
			if href, ok := cluster.Href(); ok {
				if name, ok := cluster.Name(); ok {
					clusterMap[href] = name
				}
			}
		}
	}
	return clusterMap, nil
}

// GetVM returns a specifc vm identified by name
func (c *Client) GetVM(vm *v2vv1alpha1.OVirtVM) (*kubevirtv1alpha1.OVirtVMDetail, error) {
	response, err := c.conn.SystemService().VmsService().VmService(vm.ID).Get().Send()
	if err != nil {
		return nil, err
	}
	sourceVM, ok := response.Vm()
	if !ok {
		return nil, fmt.Errorf("Virtual machine %s not found", vm.Name)
	}
	raw, err := c.getRaw(sourceVM)
	if err != nil {
		return nil, err
	}
	vmDetail := &kubevirtv1alpha1.OVirtVMDetail{
		Raw: raw,
	}
	return vmDetail, nil
}

type vm struct {
	Boot   []string        `json:"boot"`
	CPU    cpu             `json:"cpu"`
	Disks  []disk          `json:"disks"`
	ID     string          `json:"id"`
	Memory int64           `json:"memory"`
	Name   string          `json:"name"`
	Nics   []nic           `json:"nics"`
	OS     operatingSystem `json:"os"`
	VMType string          `json:"vmtype"`
}

type cpu struct {
	CPUCores int64 `json:"cores"`
	Sockets  int64 `json:"cpusockets"`
	Threads  int64 `json:"cputhreads"`
}

type operatingSystem struct {
	OsDistribution string `json:"osdist,omitempty"`
	OsType         string `json:"ostype"`
	OsVersion      string `json:"osversion,omitempty"`
}

type disk struct {
	Bootable          bool   `json:"bootable"`
	ID                string `json:"id"`
	Interface         string `json:"interface"`
	Name              string `json:"name"`
	Size              int64  `json:"size"`
	StorageDomainName string `json:"sdname"`
	StorageDomainID   string `json:"sdid"`
}

type nic struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Mac         string `json:"mac"`
	Interface   string `json:"interface"`
	NetName     string `json:"netname"`
	VnicID      string `json:"vnicid"`
	VnicNetName string `json:"vnicnetname"`
}

func (c *Client) getRaw(sourceVM *ovirtsdk.Vm) (string, error) {
	vm := &vm{}
	if vmName, ok := sourceVM.Name(); ok {
		vm.Name = vmName
	}
	if vmID, ok := sourceVM.Id(); ok {
		vm.ID = vmID
	}
	if memory, ok := sourceVM.Memory(); ok {
		vm.Memory = memory
	}
	if sourceCPU, ok := sourceVM.Cpu(); ok {
		if topology, ok := sourceCPU.Topology(); ok {
			cpu := &cpu{}
			if cores, ok := topology.Cores(); ok {
				cpu.CPUCores = cores
			}
			if sockets, ok := topology.Sockets(); ok {
				cpu.Sockets = sockets
			}
			if threads, ok := topology.Threads(); ok {
				cpu.Threads = threads
			}
			vm.CPU = *cpu
		}
	}
	os := &operatingSystem{}
	if sourceOS, ok := sourceVM.Os(); ok {
		if osType, ok := sourceOS.Type(); ok {
			os.OsType = osType
		}
		if boot, ok := sourceOS.Boot(); ok {
			if devices, ok := boot.Devices(); ok {
				for _, device := range devices {
					vm.Boot = append(vm.Boot, string(device))
				}
			}
		}
	}
	if gos, ok := sourceVM.GuestOperatingSystem(); ok {
		if dist, ok := gos.Distribution(); ok {
			os.OsDistribution = dist
		}
		if version, ok := gos.Version(); ok {
			if full, ok := version.FullVersion(); ok {
				os.OsVersion = full
			}
		}
	}
	vm.OS = *os
	if vmType, ok := sourceVM.Type(); ok {
		vm.VMType = string(vmType)
	}
	diskAttachmentsLink, _ := sourceVM.DiskAttachments()
	diskAttachments, err := c.conn.FollowLink(diskAttachmentsLink)
	if err != nil {
		return "", err
	}
	for _, diskAttachment := range diskAttachments.(*ovirtsdk.DiskAttachmentSlice).Slice() {
		disk := &disk{}
		if bootable, ok := diskAttachment.Bootable(); ok {
			disk.Bootable = bootable
		}
		if diskInterface, ok := diskAttachment.Interface(); ok {
			disk.Interface = string(diskInterface)
		}
		diskLink, _ := diskAttachment.Disk()
		vmDisk, err := c.conn.FollowLink(diskLink)
		if err != nil {
			return "", err
		}
		if size, ok := vmDisk.(*ovirtsdk.Disk).ProvisionedSize(); ok {
			disk.Size = size
		}
		if id, ok := vmDisk.(*ovirtsdk.Disk).Id(); ok {
			disk.ID = id
		}
		if name, ok := vmDisk.(*ovirtsdk.Disk).Alias(); ok {
			disk.Name = name
		}
		sdLink, _ := vmDisk.(*ovirtsdk.Disk).StorageDomains()
		sd, err := c.conn.FollowLink(sdLink.Slice()[0])
		if err != nil {
			return "", err
		}
		if sdName, ok := sd.(*ovirtsdk.StorageDomain).Name(); ok {
			disk.StorageDomainName = sdName
		}
		if sdID, ok := sd.(*ovirtsdk.StorageDomain).Id(); ok {
			disk.StorageDomainID = sdID
		}
		vm.Disks = append(vm.Disks, *disk)
	}
	nicsLink, _ := sourceVM.Nics()
	nics, err := c.conn.FollowLink(nicsLink)
	if err != nil {
		return "", err
	}
	for _, vmNic := range nics.(*ovirtsdk.NicSlice).Slice() {
		nic := &nic{}
		if name, ok := vmNic.Name(); ok {
			nic.Name = name
		}
		if id, ok := vmNic.Id(); ok {
			nic.ID = id
		}
		if mac, ok := vmNic.Mac(); ok {
			if addr, ok := mac.Address(); ok {
				nic.Mac = addr
			}
		}
		if nicInterface, ok := vmNic.Interface(); ok {
			nic.Interface = string(nicInterface)
		}
		profileLink, _ := vmNic.VnicProfile()
		profile, err := c.conn.FollowLink(profileLink)
		if err != nil {
			return "", err
		}
		vnic := profile.(*ovirtsdk.VnicProfile)
		if vnicID, ok := vnic.Id(); ok {
			nic.VnicID = vnicID
		}
		networkLink, _ := vnic.Network()
		network, err := c.conn.FollowLink(networkLink)
		if err != nil {
			return "", err
		}
		net := network.(*ovirtsdk.Network)
		if name, ok := net.Name(); ok {
			nic.NetName = name
			if vnicName, ok := vnic.Name(); ok {
				nic.VnicNetName = name + "/" + vnicName
			}
		}
		vm.Nics = append(vm.Nics, *nic)
	}
	raw, err := json.Marshal(vm)
	return string(raw), err
}
