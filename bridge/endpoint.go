package bridge

import (
	"net"
	"sync"

	"github.com/docker/libnetwork/types"
)

type endpoint struct {
	name              string
	id                string
	iface             *endpointInterface
	joinInfo          *endpointJoinInfo
	sandboxID         string
	locator           string
	exposedPorts      []types.TransportPort
	anonymous         bool
	disableResolution bool
	generic           map[string]interface{}
	joinLeaveDone     chan struct{}
	prefAddress       net.IP
	prefAddressV6     net.IP
	ipamOptions       map[string]string
	aliases           map[string]string
	myAliases         []string
	dbIndex           uint64
	dbExists          bool
	sync.Mutex
}
