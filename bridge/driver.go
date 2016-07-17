package bridge

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/network"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/options"
	"github.com/docker/libnetwork/types"
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
	ifProvided := r.Interface.Address != "" ||
		r.Interface.AddressIPv6 != "" ||
		r.Interface.MacAddress != ""

	var err error
	epi := &endpointInterface{}
	if r.Interface.Address != "" {
		epi.addr, err = parseCIDR(r.Interface.Address)
		if err != nil {
			return nil, err
		}
	}
	if r.Interface.AddressIPv6 != "" {
		epi.addrv6, err = parseCIDR(r.Interface.AddressIPv6)
		if err != nil {
			return nil, err
		}
	}
	if r.Interface.MacAddress != "" {
		epi.mac, err = net.ParseMAC(r.Interface.MacAddress)
		if err != nil {
			return nil, err
		}
	}

	if opt, ok := r.Options[netlabel.PortMap]; ok {
		pblist := []types.PortBinding{}

		for i := 0; i < len(opt.([]interface{})); i++ {
			pb := types.PortBinding{}
			tmp := opt.([]interface{})[i].(map[string]interface{})

			bytes, err := json.Marshal(tmp)
			if err != nil {
				logrus.Errorf("Couldn't remarshal the port binding")
				return nil, err
			}
			err = json.Unmarshal(bytes, &pb)
			if err != nil {
				logrus.Errorf("Couldn't unmarshal the port binding")
				return nil, err
			}
			pblist = append(pblist, pb)
		}
		r.Options[netlabel.PortMap] = pblist
	}

	if opt, ok := r.Options[netlabel.ExposedPorts]; ok {
		tplist := []types.TransportPort{}

		for i := 0; i < len(opt.([]interface{})); i++ {
			tp := types.TransportPort{}
			tmp := opt.([]interface{})[i].(map[string]interface{})

			bytes, err := json.Marshal(tmp)
			if err != nil {
				logrus.Errorf("Couldn't remarshal the exposed port")
				break
			}
			err = json.Unmarshal(bytes, &tp)
			if err != nil {
				logrus.Errorf("Couldn't unmarshal the exposed port")
				break
			}
			tplist = append(tplist, tp)
		}
		r.Options[netlabel.ExposedPorts] = tplist
	}

	err = d.driver.CreateEndpoint(r.NetworkID, r.EndpointID, epi, r.Options)
	if ifProvided {
		return &network.CreateEndpointResponse{
			Interface: nil,
		}, err
	}

	return &network.CreateEndpointResponse{
		Interface: &network.EndpointInterface{
			Address:     epi.Address().String(),
			AddressIPv6: epi.AddressIPv6().String(),
			MacAddress:  epi.MacAddress().String(),
		},
	}, err
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
	ep := &endpoint{
		joinInfo: &endpointJoinInfo{},
		iface:    &endpointInterface{},
	}
	err := d.driver.Join(
		r.NetworkID,
		r.EndpointID,
		r.SandboxKey,
		ep,
		r.Options,
	)

	staticRoutes := make([]*network.StaticRoute, 0, len(ep.joinInfo.StaticRoutes))
	for _, sr := range ep.joinInfo.StaticRoutes {
		staticRoutes = append(staticRoutes, &network.StaticRoute{
			Destination: sr.Destination.String(),
			RouteType:   sr.RouteType,
			NextHop:     sr.NextHop.String(),
		})
	}

	return &network.JoinResponse{
		InterfaceName: network.InterfaceName{
			SrcName:   ep.iface.srcName,
			DstPrefix: ep.iface.dstPrefix,
		},
		Gateway:               ep.joinInfo.gw.String(),
		GatewayIPv6:           ep.joinInfo.gw6.String(),
		StaticRoutes:          staticRoutes,
		DisableGatewayService: ep.joinInfo.disableGatewayService,
	}, err
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
