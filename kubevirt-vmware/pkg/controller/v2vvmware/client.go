package v2vvmware

/*
  Following code is based on https://github.com/pkliczewski/provider-pod
  modified for the needs of the controller-flow.
*/

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
)

type Client struct {
	Client *govmomi.Client
	ctx    context.Context
}

type LoginCredentials struct {
	host     string
	username string
	password string
}

func (c *Client) GetVMs() ([]mo.VirtualMachine, string, error) {
	var thumbprint string

	client := c.Client

	// Get thumbprint
	var info object.HostCertificateInfo
	url := client.Client.URL()
	transport := client.Client.Transport.(*http.Transport)
	err := info.FromURL(url, transport.TLSClientConfig)
	if err != nil {
		return nil, thumbprint, err
	}
	thumbprint = info.ThumbprintSHA1

	// List VMs
	m := view.NewManager(client.Client)

	v, err := m.CreateContainerView(c.ctx, client.ServiceContent.RootFolder, []string{"VirtualMachine"}, true)
	if err != nil {
		return nil, thumbprint, err
	}

	defer v.Destroy(c.ctx)

	// Reference: http://pubs.vmware.com/vsphere-60/topic/com.vmware.wssdk.apiref.doc/vim.VirtualMachine.html
	var vms []mo.VirtualMachine
	err = v.Retrieve(c.ctx, []string{"VirtualMachine"}, []string{"summary"}, &vms)
	if err != nil {
		return nil, thumbprint, err
	}

	return vms, thumbprint, nil
}

func (c *Client) GetVM(name string) (mo.VirtualMachine, string, error) {
	client := c.Client

	m := view.NewManager(client.Client)

	var vm mo.VirtualMachine
	var hostPath string

	v, err := m.CreateContainerView(c.ctx, client.ServiceContent.RootFolder, []string{"VirtualMachine"}, true)
	if err != nil {
		return vm, hostPath, err
	}

	defer v.Destroy(c.ctx)

	// Reference: http://pubs.vmware.com/vsphere-60/topic/com.vmware.wssdk.apiref.doc/vim.VirtualMachine.html
	err = v.RetrieveWithFilter(c.ctx, []string{"VirtualMachine"}, []string{"config", "summary"}, &vm, property.Filter{"summary.config.name": name})
	if err != nil {
		return vm, hostPath, err
	}

	hostPath, err = c.hostPath(vm)
	if err != nil {
		return vm, hostPath, err
	}

	return vm, hostPath, nil
}

func (c *Client) hostPath(vm mo.VirtualMachine) (string, error) {
	client := c.Client
	m := view.NewManager(client.Client)

	f := find.NewFinder(client.Client, true)
	host, err := f.ObjectReference(c.ctx, *vm.Summary.Runtime.Host)
	if err != nil {
		return "", err
	}
	var hss mo.HostSystem
	v, err := m.CreateContainerView(c.ctx, client.ServiceContent.RootFolder, []string{"HostSystem"}, true)
	defer v.Destroy(c.ctx)
	if err != nil {
		return "", err
	}
	err = v.RetrieveWithFilter(c.ctx, []string{"HostSystem"}, []string{"summary", "name", "parent"}, &hss, property.Filter{"summary.config.name": host.(*object.HostSystem).Name()})
	if err != nil {
		return "", err
	}
	pc := property.DefaultCollector(client.Client)
	var cluster mo.ManagedEntity
	err = pc.RetrieveOne(c.ctx, *hss.Parent, []string{"name"}, &cluster)
	if err != nil {
		return "", err
	}
	path := host.(*object.HostSystem).InventoryPath
	if cluster.Name == hss.Name {
		path = strings.TrimSuffix(path, "/"+hss.Name)
	}

	return path, nil
}

func (c *Client) Logout() error {
	client := c.Client
	return client.Logout(c.ctx)
}

func NewClient(ctx context.Context, credentials *LoginCredentials) (*Client, error) {
	insecure := true // TODO

	log.Info(fmt.Sprintf("NewClient, user: '%s', host: '%s'", credentials.username, credentials.host))

	if strings.IndexFunc(credentials.host, unicode.IsSpace) >= 0 {
		return nil, fmt.Errorf("host contains invalid white space characters: %v", credentials.host)
	}

	host, err := parseHost(credentials.host)

	if err != nil {
		return nil, err
	}

	u := &url.URL{
		Scheme: "https", // force TLS
		User:   url.UserPassword(credentials.username, credentials.password),
		Host:   host,
		Path:   vim25.Path,
	}

	// still check the URL validity and fail early, so the client doesn't panic later when creating requests
	if _, err := url.Parse(u.String()); err != nil {
		return nil, err
	}

	// Connect and log in to ESX or vCenter
	client, err := govmomi.NewClient(ctx, u, insecure)
	if err != nil {
		return nil, err
	}

	c := &Client{
		Client: client,
		ctx:    ctx,
	}
	return c, nil
}

func parseHost(rawURL string) (string, error) {
	if strings.IndexFunc(rawURL, unicode.IsSpace) >= 0 {
		return "", fmt.Errorf("host contains invalid white space characters: %v", rawURL)
	}

	u, err := url.Parse(rawURL)

	if err != nil || u.Scheme == "" {
		// try again with a scheme, to parse the url in the general form
		u, err = url.Parse("https://" + rawURL)
	}

	if err != nil {
		return "", err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("host does not have a supported scheme: %v", rawURL)
	}

	if u.Host != "" {
		return u.Host, nil
	}

	// default to original if host not found
	return rawURL, nil
}
