package bridge

import (
	"fmt"
	"net"
)

// ErrInvalidDriverConfig error is returned when Bridge Driver is passed an invalid config
type ErrInvalidDriverConfig struct{}

func (eidc *ErrInvalidDriverConfig) Error() string {
	return "Invalid configuration passed to Bridge Driver"
}

// ErrInvalidEndpointConfig error is returned when a endpoint create is attempted with an invalid endpoint configuration.
type ErrInvalidEndpointConfig struct{}

func (eiec *ErrInvalidEndpointConfig) Error() string {
	return "trying to create an endpoint with an invalid endpoint configuration"
}

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

// ErrUnsupportedAddressType is returned when the specified address type is not supported.
type ErrUnsupportedAddressType string

func (uat ErrUnsupportedAddressType) Error() string {
	return fmt.Sprintf("unsupported address type: %s", string(uat))
}

// ActiveEndpointsError is returned when there are
// still active endpoints in the network being deleted.
type ActiveEndpointsError string

func (aee ActiveEndpointsError) Error() string {
	return fmt.Sprintf("network %s has active endpoint", string(aee))
}

// InvalidNetworkIDError is returned when the passed
// network id for an existing network is not a known id.
type InvalidNetworkIDError string

func (inie InvalidNetworkIDError) Error() string {
	return fmt.Sprintf("invalid network id %s", string(inie))
}

// InvalidEndpointIDError is returned when the passed
// endpoint id is not valid.
type InvalidEndpointIDError string

func (ieie InvalidEndpointIDError) Error() string {
	return fmt.Sprintf("invalid endpoint id: %s", string(ieie))
}

// EndpointNotFoundError is returned when the no endpoint
// with the passed endpoint id is found.
type EndpointNotFoundError string

func (enfe EndpointNotFoundError) Error() string {
	return fmt.Sprintf("endpoint not found: %s", string(enfe))
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

// InvalidIPTablesCfgError is returned when an invalid ip tables configuration is entered
type InvalidIPTablesCfgError string

func (action InvalidIPTablesCfgError) Error() string {
	return fmt.Sprintf("Invalid IPTables action '%s'", string(action))
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

// InvalidLinkIPAddrError is returned when a link is configured to a container with an invalid ip address
type InvalidLinkIPAddrError string

func (address InvalidLinkIPAddrError) Error() string {
	return fmt.Sprintf("Cannot link to a container with Invalid IP Address '%s'", string(address))
}
