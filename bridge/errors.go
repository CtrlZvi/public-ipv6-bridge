package bridge

import (
	"fmt"
	"net"
)

// ErrNoIPAddr error is returned when bridge has no IPv4 address configured.
type ErrNoIPAddr struct{}

func (enip *ErrNoIPAddr) Error() string {
	return "bridge has no IPv4 address configured"
}

// ErrInvalidGateway is returned when the user provided default gateway (v4/v6) is not not valid.
type ErrInvalidGateway struct{}

func (eig *ErrInvalidGateway) Error() string {
	return "default gateway ip must be part of the network"
}

// ErrInvalidContainerSubnet is returned when the container subnet (FixedCIDR) is not valid.
type ErrInvalidContainerSubnet struct{}

func (eis *ErrInvalidContainerSubnet) Error() string {
	return "container subnet must be a subset of bridge network"
}

// ErrInvalidMtu is returned when the user provided MTU is not valid.
type ErrInvalidMtu int

func (eim ErrInvalidMtu) Error() string {
	return fmt.Sprintf("invalid MTU number: %d", int(eim))
}

// ActiveEndpointsError is returned when there are
// still active endpoints in the network being deleted.
type ActiveEndpointsError string

func (aee ActiveEndpointsError) Error() string {
	return fmt.Sprintf("network %s has active endpoint", string(aee))
}

// NonDefaultBridgeExistError is returned when a non-default
// bridge config is passed but it does not already exist.
type NonDefaultBridgeExistError string

func (ndbee NonDefaultBridgeExistError) Error() string {
	return fmt.Sprintf("bridge device with non default name %s must be created manually", string(ndbee))
}

// IPTableCfgError is returned when an unexpected ip tables configuration is entered
type IPTableCfgError string

func (name IPTableCfgError) Error() string {
	return fmt.Sprintf("unexpected request to set IP tables for interface: %s", string(name))
}

// IPv4AddrAddError is returned when IPv4 address could not be added to the bridge.
type IPv4AddrAddError struct {
	IP  *net.IPNet
	Err error
}

func (ipv4 *IPv4AddrAddError) Error() string {
	return fmt.Sprintf("failed to add IPv4 address %s to bridge: %v", ipv4.IP, ipv4.Err)
}

// IPv6AddrAddError is returned when IPv6 address could not be added to the bridge.
type IPv6AddrAddError struct {
	IP  *net.IPNet
	Err error
}

func (ipv6 *IPv6AddrAddError) Error() string {
	return fmt.Sprintf("failed to add IPv6 address %s to bridge: %v", ipv6.IP, ipv6.Err)
}

// IPv4AddrNoMatchError is returned when the bridge's IPv4 address does not match configured.
type IPv4AddrNoMatchError struct {
	IP    net.IP
	CfgIP net.IP
}

func (ipv4 *IPv4AddrNoMatchError) Error() string {
	return fmt.Sprintf("bridge IPv4 (%s) does not match requested configuration %s", ipv4.IP, ipv4.CfgIP)
}

// IPv6AddrNoMatchError is returned when the bridge's IPv6 address does not match configured.
type IPv6AddrNoMatchError net.IPNet

func (ipv6 *IPv6AddrNoMatchError) Error() string {
	return fmt.Sprintf("bridge IPv6 addresses do not match the expected bridge configuration %s", (*net.IPNet)(ipv6).String())
}
