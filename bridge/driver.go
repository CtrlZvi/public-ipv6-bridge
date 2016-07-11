package bridge

import (
	"fmt"
	"net"

	"github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/network"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/options"
)

// Driver is a wrapper around the bridge driver to make it support the
// network.Driver interface.
type Driver struct {
	driver     *driver
	capability driverapi.Capability
}

// NewDriver creates a new bridge driver.
func NewDriver(d driverapi.Driver, c driverapi.Capability) *Driver {
	return &Driver{
		driver:     d.(*driver),
		capability: c,
	}
}

// GetCapabilities implements network.Driver.GetCapabilities().
func (d *Driver) GetCapabilities() (*network.CapabilitiesResponse, error) {
	return &network.CapabilitiesResponse{
		Scope: d.capability.DataScope,
	}, nil
}

// CreateNetwork implements network.Driver.CreateNetwork().
func (d *Driver) CreateNetwork(r *network.CreateNetworkRequest) error {
	ipv4Data, err := convertIPAMData(r.IPv4Data)
	if err != nil {
		return err
	}
	ipv6Data, err := convertIPAMData(r.IPv6Data)
	if err != nil {
		return err
	}
	option := options.Generic{
		netlabel.GenericData: map[string]string{},
	}
	for label, opt := range r.Options {
		switch opt := opt.(type) {
		case map[string]interface{}:
			for label, value := range opt {
				option[netlabel.GenericData].(map[string]string)[label] = value.(string)
			}
		default:
			panic(label)
		}
	}
	return d.driver.CreateNetwork(r.NetworkID, option, ipv4Data, ipv6Data)
}

// DeleteNetwork implements network.Driver.DeleteNetwork().
func (d *Driver) DeleteNetwork(r *network.DeleteNetworkRequest) error {
	return d.driver.DeleteNetwork(r.NetworkID)
}

// CreateEndpoint implements network.Driver.CreateEndpoint().
func (d *Driver) CreateEndpoint(r *network.CreateEndpointRequest) (*network.CreateEndpointResponse, error) {
	logrus.Warnf("Call to unimplemented CreateEndpoint")
	return nil, fmt.Errorf("Not implemented")
}

// DeleteEndpoint implements network.Driver.DeleteEndpoint().
func (d *Driver) DeleteEndpoint(r *network.DeleteEndpointRequest) error {
	logrus.Warnf("Call to unimplemented DeleteEndpoint")
	return fmt.Errorf("Not implemented")
}

// EndpointInfo implements network.Driver.EndpointInfo().
func (d *Driver) EndpointInfo(r *network.InfoRequest) (*network.InfoResponse, error) {
	logrus.Warnf("Call to unimplemented EndpointInfo")
	return nil, fmt.Errorf("Not implemented")
}

// Join implements network.Driver.Join().
func (d *Driver) Join(r *network.JoinRequest) (*network.JoinResponse, error) {
	logrus.Warnf("Call to unimplemented Join")
	return nil, fmt.Errorf("Not implemented")
}

// Leave implements network.Driver.Leave().
func (d *Driver) Leave(r *network.LeaveRequest) error {
	logrus.Warnf("Call to unimplemented Leave")
	return fmt.Errorf("Not implemented")
}

// DiscoverNew implements network.Driver.DiscoverNew().
func (d *Driver) DiscoverNew(n *network.DiscoveryNotification) error {
	logrus.Warnf("Call to unimplemented DiscoverNew")
	return fmt.Errorf("Not implemented")
}

// DiscoverDelete implements network.Driver.DiscoverDelete().
func (d *Driver) DiscoverDelete(n *network.DiscoveryNotification) error {
	logrus.Warnf("Call to unimplemented DiscoverDelete")
	return fmt.Errorf("Not implemented")
}

// ProgramExternalConnectivity implements
// network.Driver.ProgramExternalConnectivity().
func (d *Driver) ProgramExternalConnectivity(*network.ProgramExternalConnectivityRequest) error {
	logrus.Warnf("Call to unimplemented ProgramExternalConnectivity")
	return fmt.Errorf("Not implemented")
}

// RevokeExternalConnectivity implements
// network.Driver.RevokeExternalConnectivity().
func (d *Driver) RevokeExternalConnectivity(*network.RevokeExternalConnectivityRequest) error {
	logrus.Warnf("Call to unimplemented RevokeExternalConnectivity")
	return fmt.Errorf("Not implemented")
}

func convertIPAMData(ipamData []*network.IPAMData) ([]driverapi.IPAMData, error) {
	res := make([]driverapi.IPAMData, 0, len(ipamData))
	for _, i := range ipamData {
		pool, err := parseCIDR(i.Pool)
		if err != nil {
			return nil, err
		}
		gateway, err := parseCIDR(i.Gateway)
		if err != nil {
			return nil, err
		}
		auxAddresses := make(map[string]*net.IPNet)
		for id, addr := range i.AuxAddresses {
			auxAddresses[id], err = parseCIDR(addr.(string))
			if err != nil {
				return nil, err
			}
		}
		res = append(res, driverapi.IPAMData{
			AddressSpace: i.AddressSpace,
			Pool:         pool,
			Gateway:      gateway,
			AuxAddresses: auxAddresses,
		})
	}
	return res, nil
}

func parseCIDR(cidr string) (*net.IPNet, error) {
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	subnet.IP = ip
	return subnet, nil
}
