package bridge

import "github.com/CtrlZvi/public-ipv6-bridge/iptables"

func (n *bridgeNetwork) setupFirewalld(config *networkConfiguration, i *bridgeInterface) error {
	d := n.driver
	d.Lock()
	driverConfig := d.config
	d.Unlock()

	// Sanity check.
	if driverConfig.EnableIPTables == false {
		return IPTableCfgError(config.BridgeName)
	}

	iptables.OnReloaded(func() { n.setupIPTables(config, i) })
	iptables.OnReloaded(n.portMapper.ReMapAll)
	iptables.OnReloaded(func() { n.setupIPv6Tables(config, i) })

	return nil
}
