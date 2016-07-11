package bridge

import (
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/network"
)

// Driver is a wrapper around the bridge driver to make it support the
// network.Driver interface.
type Driver struct {
}

// NewDriver creates a new bridge driver.
func NewDriver() *Driver {
	return &Driver{}
}

// GetCapabilities implements network.Driver.GetCapabilities().
func (d *Driver) GetCapabilities() (*network.CapabilitiesResponse, error) {
	logrus.Warnf("Call to unimplemented GetCapabilities")
	return nil, fmt.Errorf("Not implemented")
}

// CreateNetwork implements network.Driver.CreateNetwork().
func (d *Driver) CreateNetwork(r *network.CreateNetworkRequest) error {
	logrus.Warnf("Call to unimplemented CreateNetwork")
	return fmt.Errorf("Not implemented")
}

// DeleteNetwork implements network.Driver.DeleteNetwork().
func (d *Driver) DeleteNetwork(r *network.DeleteNetworkRequest) error {
	logrus.Warnf("Call to unimplemented DeleteNetwork")
	return fmt.Errorf("Not implemented")
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
