package bridge

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/iptables"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/options"
	"github.com/docker/libnetwork/osl"
	"github.com/docker/libnetwork/portmapper"
	"github.com/docker/libnetwork/types"
	"github.com/vishvananda/netlink"
)

const (
	// DefaultGatewayV4AuxKey represents the default-gateway configured by the user
	DefaultGatewayV4AuxKey = "DefaultGatewayIPv4"
	// DefaultGatewayV6AuxKey represents the ipv6 default-gateway configured by the user
	DefaultGatewayV6AuxKey = "DefaultGatewayIPv6"
)

type iptableCleanFunc func() error
type iptablesCleanFuncs []iptableCleanFunc

// configuration info for the "bridge" driver.
type configuration struct {
	EnableIPForwarding  bool
	EnableIPTables      bool
	EnableUserlandProxy bool
}

// networkConfiguration for network specific configuration
type networkConfiguration struct {
	ID                 string
	BridgeName         string
	EnableIPv6         bool
	EnableIPMasquerade bool
	EnableICC          bool
	Mtu                int
	DefaultBindingIP   net.IP
	DefaultBridge      bool
	// Internal fields set after ipam data parsing
	AddressIPv4        *net.IPNet
	AddressIPv6        *net.IPNet
	DefaultGatewayIPv4 net.IP
	DefaultGatewayIPv6 net.IP
	dbIndex            uint64
	dbExists           bool
	Internal           bool
}

// endpointConfiguration represents the user specified configuration for the sandbox endpoint
type endpointConfiguration struct {
	MacAddress   net.HardwareAddr
	PortBindings []types.PortBinding
	ExposedPorts []types.TransportPort
}

// containerConfiguration represents the user specified configuration for a container
type containerConfiguration struct {
	ParentEndpoints []string
	ChildEndpoints  []string
}

type bridgeEndpoint struct {
	id              string
	srcName         string
	addr            *net.IPNet
	addrv6          *net.IPNet
	macAddress      net.HardwareAddr
	config          *endpointConfiguration // User specified parameters
	containerConfig *containerConfiguration
	portMapping     []types.PortBinding // Operation port bindings
}

type bridgeNetwork struct {
	id            string
	bridge        *bridgeInterface // The bridge's L3 interface
	config        *networkConfiguration
	endpoints     map[string]*bridgeEndpoint // key: endpoint id
	portMapper    *portmapper.PortMapper
	driver        *driver // The network's driver
	iptCleanFuncs iptablesCleanFuncs
	sync.Mutex
}

type driver struct {
	config         *configuration
	network        *bridgeNetwork
	natChain       *iptables.ChainInfo
	filterChain    *iptables.ChainInfo
	isolationChain *iptables.ChainInfo
	networks       map[string]*bridgeNetwork
	store          datastore.DataStore
	sync.Mutex
}

// New constructs a new bridge driver
func newDriver() *driver {
	return &driver{networks: map[string]*bridgeNetwork{}, config: &configuration{}}
}

// Validate performs a static validation on the network configuration parameters.
// Whatever can be assessed a priori before attempting any programming.
func (c *networkConfiguration) Validate() error {
	if c.Mtu < 0 {
		return ErrInvalidMtu(c.Mtu)
	}

	// If bridge v4 subnet is specified
	if c.AddressIPv4 != nil {
		// If default gw is specified, it must be part of bridge subnet
		if c.DefaultGatewayIPv4 != nil {
			if !c.AddressIPv4.Contains(c.DefaultGatewayIPv4) {
				return &ErrInvalidGateway{}
			}
		}
	}

	// If default v6 gw is specified, AddressIPv6 must be specified and gw must belong to AddressIPv6 subnet
	if c.EnableIPv6 && c.DefaultGatewayIPv6 != nil {
		if c.AddressIPv6 == nil || !c.AddressIPv6.Contains(c.DefaultGatewayIPv6) {
			return &ErrInvalidGateway{}
		}
	}
	return nil
}

// Conflicts check if two NetworkConfiguration objects overlap
func (c *networkConfiguration) Conflicts(o *networkConfiguration) error {
	if o == nil {
		return fmt.Errorf("same configuration")
	}

	// Also empty, becasue only one network with empty name is allowed
	if c.BridgeName == o.BridgeName {
		return fmt.Errorf("networks have same bridge name")
	}

	// They must be in different subnets
	if (c.AddressIPv4 != nil && o.AddressIPv4 != nil) &&
		(c.AddressIPv4.Contains(o.AddressIPv4.IP) || o.AddressIPv4.Contains(c.AddressIPv4.IP)) {
		return fmt.Errorf("networks have overlapping IPv4")
	}

	// They must be in different v6 subnets
	if (c.AddressIPv6 != nil && o.AddressIPv6 != nil) &&
		(c.AddressIPv6.Contains(o.AddressIPv6.IP) || o.AddressIPv6.Contains(c.AddressIPv6.IP)) {
		return fmt.Errorf("networks have overlapping IPv6")
	}

	return nil
}

func (c *networkConfiguration) fromLabels(labels map[string]string) error {
	var err error
	for label, value := range labels {
		switch label {
		case BridgeName:
			c.BridgeName = value
		case netlabel.DriverMTU:
			if c.Mtu, err = strconv.Atoi(value); err != nil {
				return parseErr(label, value, err.Error())
			}
		case netlabel.EnableIPv6:
			if c.EnableIPv6, err = strconv.ParseBool(value); err != nil {
				return parseErr(label, value, err.Error())
			}
		case EnableIPMasquerade:
			if c.EnableIPMasquerade, err = strconv.ParseBool(value); err != nil {
				return parseErr(label, value, err.Error())
			}
		case EnableICC:
			if c.EnableICC, err = strconv.ParseBool(value); err != nil {
				return parseErr(label, value, err.Error())
			}
		case DefaultBridge:
			if c.DefaultBridge, err = strconv.ParseBool(value); err != nil {
				return parseErr(label, value, err.Error())
			}
		case DefaultBindingIP:
			if c.DefaultBindingIP = net.ParseIP(value); c.DefaultBindingIP == nil {
				return parseErr(label, value, "nil ip")
			}
		}
	}

	return nil
}

func parseErr(label, value, errString string) error {
	return types.BadRequestErrorf("failed to parse %s value: %v (%s)", label, value, errString)
}

func (n *bridgeNetwork) registerIptCleanFunc(clean iptableCleanFunc) {
	n.iptCleanFuncs = append(n.iptCleanFuncs, clean)
}

func (n *bridgeNetwork) getDriverChains() (*iptables.ChainInfo, *iptables.ChainInfo, *iptables.ChainInfo, error) {
	n.Lock()
	defer n.Unlock()

	if n.driver == nil {
		return nil, nil, nil, types.BadRequestErrorf("no driver found")
	}

	return n.driver.natChain, n.driver.filterChain, n.driver.isolationChain, nil
}

func (n *bridgeNetwork) getNetworkBridgeName() string {
	n.Lock()
	config := n.config
	n.Unlock()

	return config.BridgeName
}

// Install/Removes the iptables rules needed to isolate this network
// from each of the other networks
func (n *bridgeNetwork) isolateNetwork(others []*bridgeNetwork, enable bool) error {
	n.Lock()
	thisConfig := n.config
	n.Unlock()

	if thisConfig.Internal {
		return nil
	}

	// Install the rules to isolate this networks against each of the other networks
	for _, o := range others {
		o.Lock()
		otherConfig := o.config
		o.Unlock()

		if otherConfig.Internal {
			continue
		}

		if thisConfig.BridgeName != otherConfig.BridgeName {
			if err := setINC(thisConfig.BridgeName, otherConfig.BridgeName, enable); err != nil {
				return err
			}
		}
	}

	return nil
}

// Checks whether this network's configuration for the network with this id conflicts with any of the passed networks
func (c *networkConfiguration) conflictsWithNetworks(id string, others []*bridgeNetwork) error {
	for _, nw := range others {

		nw.Lock()
		nwID := nw.id
		nwConfig := nw.config
		nwBridge := nw.bridge
		nw.Unlock()

		if nwID == id {
			continue
		}
		// Verify the name (which may have been set by newInterface()) does not conflict with
		// existing bridge interfaces. Ironically the system chosen name gets stored in the config...
		// Basically we are checking if the two original configs were both empty.
		if nwConfig.BridgeName == c.BridgeName {
			return types.ForbiddenErrorf("conflicts with network %s (%s) by bridge name", nwID, nwConfig.BridgeName)
		}
		// If this network config specifies the AddressIPv4, we need
		// to make sure it does not conflict with any previously allocated
		// bridges. This could not be completely caught by the config conflict
		// check, because networks which config does not specify the AddressIPv4
		// get their address and subnet selected by the driver (see electBridgeIPv4())
		if c.AddressIPv4 != nil {
			if nwBridge.bridgeIPv4.Contains(c.AddressIPv4.IP) ||
				c.AddressIPv4.Contains(nwBridge.bridgeIPv4.IP) {
				return types.ForbiddenErrorf("conflicts with network %s (%s) by ip network", nwID, nwConfig.BridgeName)
			}
		}
	}

	return nil
}

func parseNetworkGenericOptions(data interface{}) (*networkConfiguration, error) {
	var (
		err    error
		config *networkConfiguration
	)

	switch opt := data.(type) {
	case *networkConfiguration:
		config = opt
	case map[string]string:
		config = &networkConfiguration{
			EnableICC:          true,
			EnableIPMasquerade: true,
		}
		err = config.fromLabels(opt)
	case options.Generic:
		var opaqueConfig interface{}
		if opaqueConfig, err = options.GenerateFromModel(opt, config); err == nil {
			config = opaqueConfig.(*networkConfiguration)
		}
	default:
		err = types.BadRequestErrorf("do not recognize network configuration format: %T", opt)
	}

	return config, err
}

func (c *networkConfiguration) processIPAM(id string, ipamV4Data, ipamV6Data []driverapi.IPAMData) error {
	if len(ipamV4Data) > 1 || len(ipamV6Data) > 1 {
		return types.ForbiddenErrorf("bridge driver doesnt support multiple subnets")
	}

	if len(ipamV4Data) == 0 {
		return types.BadRequestErrorf("bridge network %s requires ipv4 configuration", id)
	}

	if ipamV4Data[0].Gateway != nil {
		c.AddressIPv4 = types.GetIPNetCopy(ipamV4Data[0].Gateway)
	}

	if gw, ok := ipamV4Data[0].AuxAddresses[DefaultGatewayV4AuxKey]; ok {
		c.DefaultGatewayIPv4 = gw.IP
	}

	if len(ipamV6Data) > 0 {
		c.AddressIPv6 = ipamV6Data[0].Pool

		if ipamV6Data[0].Gateway != nil {
			c.AddressIPv6 = types.GetIPNetCopy(ipamV6Data[0].Gateway)
		}

		if gw, ok := ipamV6Data[0].AuxAddresses[DefaultGatewayV6AuxKey]; ok {
			c.DefaultGatewayIPv6 = gw.IP
		}
	}

	return nil
}

func parseNetworkOptions(id string, option options.Generic) (*networkConfiguration, error) {
	var (
		err    error
		config = &networkConfiguration{}
	)

	// Parse generic label first, config will be re-assigned
	if genData, ok := option[netlabel.GenericData]; ok && genData != nil {
		if config, err = parseNetworkGenericOptions(genData); err != nil {
			return nil, err
		}
	}

	// Process well-known labels next
	if val, ok := option[netlabel.EnableIPv6]; ok {
		config.EnableIPv6 = val.(bool)
	}

	if val, ok := option[netlabel.Internal]; ok {
		if internal, ok := val.(bool); ok && internal {
			config.Internal = true
		}
	}

	// Finally validate the configuration
	if err = config.Validate(); err != nil {
		return nil, err
	}

	if config.BridgeName == "" && config.DefaultBridge == false {
		config.BridgeName = "br-" + id[:12]
	}

	config.ID = id
	return config, nil
}

// Return a slice of networks over which caller can iterate safely
func (d *driver) getNetworks() []*bridgeNetwork {
	d.Lock()
	defer d.Unlock()

	ls := make([]*bridgeNetwork, 0, len(d.networks))
	for _, nw := range d.networks {
		ls = append(ls, nw)
	}
	return ls
}

// Create a new network using bridge plugin
func (d *driver) CreateNetwork(id string, option map[string]interface{}, ipV4Data, ipV6Data []driverapi.IPAMData) error {
	// Sanity checks
	d.Lock()
	if _, ok := d.networks[id]; ok {
		d.Unlock()
		return types.ForbiddenErrorf("network %s exists", id)
	}
	d.Unlock()

	// Parse and validate the config. It should not conflict with existing networks' config
	config, err := parseNetworkOptions(id, option)
	if err != nil {
		return err
	}

	err = config.processIPAM(id, ipV4Data, ipV6Data)
	if err != nil {
		return err
	}

	if err = d.createNetwork(config); err != nil {
		return err
	}

	return d.storeUpdate(config)
}

func (d *driver) createNetwork(config *networkConfiguration) error {
	var err error

	defer osl.InitOSContext()()

	networkList := d.getNetworks()
	for _, nw := range networkList {
		nw.Lock()
		nwConfig := nw.config
		nw.Unlock()
		if err := nwConfig.Conflicts(config); err != nil {
			return types.ForbiddenErrorf("cannot create network %s (%s): conflicts with network %s (%s): %s",
				nwConfig.BridgeName, config.ID, nw.id, nw.config.BridgeName, err.Error())
		}
	}

	// Create and set network handler in driver
	network := &bridgeNetwork{
		id:         config.ID,
		endpoints:  make(map[string]*bridgeEndpoint),
		config:     config,
		portMapper: portmapper.New(),
		driver:     d,
	}

	d.Lock()
	d.networks[config.ID] = network
	d.Unlock()

	// On failure make sure to reset driver network handler to nil
	defer func() {
		if err != nil {
			d.Lock()
			delete(d.networks, config.ID)
			d.Unlock()
		}
	}()

	// Create or retrieve the bridge L3 interface
	bridgeIface := newInterface(config)
	network.bridge = bridgeIface

	// Verify the network configuration does not conflict with previously installed
	// networks. This step is needed now because driver might have now set the bridge
	// name on this config struct. And because we need to check for possible address
	// conflicts, so we need to check against operationa lnetworks.
	if err = config.conflictsWithNetworks(config.ID, networkList); err != nil {
		return err
	}

	setupNetworkIsolationRules := func(config *networkConfiguration, i *bridgeInterface) error {
		if err := network.isolateNetwork(networkList, true); err != nil {
			if err := network.isolateNetwork(networkList, false); err != nil {
				logrus.Warnf("Failed on removing the inter-network iptables rules on cleanup: %v", err)
			}
			return err
		}
		network.registerIptCleanFunc(func() error {
			nwList := d.getNetworks()
			return network.isolateNetwork(nwList, false)
		})
		return nil
	}

	// Prepare the bridge setup configuration
	bridgeSetup := newBridgeSetup(config, bridgeIface)

	// If the bridge interface doesn't exist, we need to start the setup steps
	// by creating a new device and assigning it an IPv4 address.
	bridgeAlreadyExists := bridgeIface.exists()
	if !bridgeAlreadyExists {
		bridgeSetup.queueStep(setupDevice)
	}

	// Even if a bridge exists try to setup IPv4.
	bridgeSetup.queueStep(setupBridgeIPv4)

	enableIPv6Forwarding := d.config.EnableIPForwarding && config.AddressIPv6 != nil

	// Conditionally queue setup steps depending on configuration values.
	for _, step := range []struct {
		Condition bool
		Fn        setupStep
	}{
		// Enable IPv6 on the bridge if required. We do this even for a
		// previously  existing bridge, as it may be here from a previous
		// installation where IPv6 wasn't supported yet and needs to be
		// assigned an IPv6 link-local address.
		{config.EnableIPv6, setupBridgeIPv6},

		// We ensure that the bridge has the expectedIPv4 and IPv6 addresses in
		// the case of a previously existing device.
		{bridgeAlreadyExists, setupVerifyAndReconcile},

		// Enable IPv6 Forwarding
		{enableIPv6Forwarding, setupIPv6Forwarding},

		// Setup Loopback Adresses Routing
		{!d.config.EnableUserlandProxy, setupLoopbackAdressesRouting},

		// Setup IPTables.
		{d.config.EnableIPTables, network.setupIPTables},

		//We want to track firewalld configuration so that
		//if it is started/reloaded, the rules can be applied correctly
		{d.config.EnableIPTables, network.setupFirewalld},

		// Setup DefaultGatewayIPv4
		{config.DefaultGatewayIPv4 != nil, setupGatewayIPv4},

		// Setup DefaultGatewayIPv6
		{config.DefaultGatewayIPv6 != nil, setupGatewayIPv6},

		// Add inter-network communication rules.
		{d.config.EnableIPTables, setupNetworkIsolationRules},

		//Configure bridge networking filtering if ICC is off and IP tables are enabled
		{!config.EnableICC && d.config.EnableIPTables, setupBridgeNetFiltering},
	} {
		if step.Condition {
			bridgeSetup.queueStep(step.Fn)
		}
	}

	// Apply the prepared list of steps, and abort at the first error.
	bridgeSetup.queueStep(setupDeviceUp)
	if err = bridgeSetup.apply(); err != nil {
		return err
	}

	return nil
}

func (d *driver) DeleteNetwork(nid string) error {
	var err error

	defer osl.InitOSContext()()

	// Get network handler and remove it from driver
	d.Lock()
	n, ok := d.networks[nid]
	d.Unlock()

	if !ok {
		return types.InternalMaskableErrorf("network %s does not exist", nid)
	}

	n.Lock()
	config := n.config
	n.Unlock()

	d.Lock()
	delete(d.networks, nid)
	d.Unlock()

	// On failure set network handler back in driver, but
	// only if is not already taken over by some other thread
	defer func() {
		if err != nil {
			d.Lock()
			if _, ok := d.networks[nid]; !ok {
				d.networks[nid] = n
			}
			d.Unlock()
		}
	}()

	// Sanity check
	if n == nil {
		err = driverapi.ErrNoNetwork(nid)
		return err
	}

	// Cannot remove network if endpoints are still present
	if len(n.endpoints) != 0 {
		err = ActiveEndpointsError(n.id)
		return err
	}

	// We only delete the bridge when it's not the default bridge. This is keep the backward compatible behavior.
	if !config.DefaultBridge {
		if err := netlink.LinkDel(n.bridge.Link); err != nil {
			logrus.Warnf("Failed to remove bridge interface %s on network %s delete: %v", config.BridgeName, nid, err)
		}
	}

	// clean all relevant iptables rules
	for _, cleanFunc := range n.iptCleanFuncs {
		if errClean := cleanFunc(); errClean != nil {
			logrus.Warnf("Failed to clean iptables rules for bridge network: %v", errClean)
		}
	}
	return d.storeDelete(config)
}
