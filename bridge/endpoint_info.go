package bridge

import (
	"net"

	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/types"
)

type endpointInterface struct {
	mac       net.HardwareAddr
	addr      *net.IPNet
	addrv6    *net.IPNet
	srcName   string
	dstPrefix string
	routes    []*net.IPNet
	v4PoolID  string
	v6PoolID  string
}

type endpointJoinInfo struct {
	gw                    net.IP
	gw6                   net.IP
	StaticRoutes          []*types.StaticRoute
	disableGatewayService bool
}

func (epi *endpointInterface) SetMacAddress(mac net.HardwareAddr) error {
	if epi.mac != nil {
		return types.ForbiddenErrorf("endpoint interface MAC address present (%s). Cannot be modified with %s.", epi.mac, mac)
	}
	if mac == nil {
		return types.BadRequestErrorf("tried to set nil MAC address to endpoint interface")
	}
	epi.mac = types.GetMacCopy(mac)
	return nil
}

func (epi *endpointInterface) SetIPAddress(address *net.IPNet) error {
	if address.IP == nil {
		return types.BadRequestErrorf("tried to set nil IP address to endpoint interface")
	}
	if address.IP.To4() == nil {
		return setAddress(&epi.addrv6, address)
	}
	return setAddress(&epi.addr, address)
}

func setAddress(ifaceAddr **net.IPNet, address *net.IPNet) error {
	if *ifaceAddr != nil {
		return types.ForbiddenErrorf("endpoint interface IP present (%s). Cannot be modified with (%s).", *ifaceAddr, address)
	}
	*ifaceAddr = types.GetIPNetCopy(address)
	return nil
}

func (epi *endpointInterface) MacAddress() net.HardwareAddr {
	return types.GetMacCopy(epi.mac)
}

func (epi *endpointInterface) Address() *net.IPNet {
	return types.GetIPNetCopy(epi.addr)
}

func (epi *endpointInterface) AddressIPv6() *net.IPNet {
	return types.GetIPNetCopy(epi.addrv6)
}

func (epi *endpointInterface) SetNames(srcName string, dstPrefix string) error {
	epi.srcName = srcName
	epi.dstPrefix = dstPrefix
	return nil
}

func (ep *endpoint) InterfaceName() driverapi.InterfaceNameInfo {
	ep.Lock()
	defer ep.Unlock()

	if ep.iface != nil {
		return ep.iface
	}

	return nil
}

func (ep *endpoint) AddStaticRoute(destination *net.IPNet, routeType int, nextHop net.IP) error {
	ep.Lock()
	defer ep.Unlock()

	r := types.StaticRoute{Destination: destination, RouteType: routeType, NextHop: nextHop}

	if routeType == types.NEXTHOP {
		// If the route specifies a next-hop, then it's loosely routed (i.e. not bound to a particular interface).
		ep.joinInfo.StaticRoutes = append(ep.joinInfo.StaticRoutes, &r)
	} else {
		// If the route doesn't specify a next-hop, it must be a connected route, bound to an interface.
		ep.iface.routes = append(ep.iface.routes, r.Destination)
	}
	return nil
}

func (ep *endpoint) SetGateway(gw net.IP) error {
	ep.Lock()
	defer ep.Unlock()

	ep.joinInfo.gw = types.GetIPCopy(gw)
	return nil
}

func (ep *endpoint) SetGatewayIPv6(gw6 net.IP) error {
	ep.Lock()
	defer ep.Unlock()

	ep.joinInfo.gw6 = types.GetIPCopy(gw6)
	return nil
}

func (ep *endpoint) DisableGatewayService() {
	ep.Lock()
	defer ep.Unlock()

	ep.joinInfo.disableGatewayService = true
}
