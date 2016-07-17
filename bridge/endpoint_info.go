package bridge

import (
	"net"

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
