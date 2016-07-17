package main

import (
	"fmt"

	"github.com/CtrlZvi/public-ipv6-bridge/bridge"
	"github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/network"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/options"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	pluginName = "public-ipv6-bridge"
)

var (
	debug     = kingpin.Flag("debug", "Enable debug mode").Short('D').Default("false").Bool()
	iptables  = kingpin.Flag("iptables", "Enable addition of iptables rules").Default("true").Bool()
	ipForward = kingpin.Flag("ip-forward", "Enable net.ipv4.ip_forward").Default("true").Bool()
)

type driverCallback struct {
	driver *bridge.Driver
}

func (dc *driverCallback) RegisterDriver(n string, d driverapi.Driver, c driverapi.Capability) error {
	if n != pluginName {
		return fmt.Errorf("Unsupported network type: %s", n)
	}
	dc.driver = bridge.NewDriver(d, c)

	return nil
}

func main() {
	kingpin.Parse()
	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	dc := &driverCallback{}
	driverOptions := options.Generic{
		"EnableIPTables":     *iptables,
		"EnableIPForwarding": *ipForward,
	}
	genericOption := make(map[string]interface{})
	genericOption[netlabel.GenericData] = driverOptions
	for k, v := range datastore.DefaultScopes("") {
		if !v.IsValid() {
			continue
		}

		genericOption[netlabel.MakeKVProvider(k)] = v.Client.Provider
		genericOption[netlabel.MakeKVProviderURL(k)] = v.Client.Address
		genericOption[netlabel.MakeKVProviderConfig(k)] = v.Client.Config
	}

	err := bridge.Init(dc, genericOption)
	if err != nil {
		logrus.Fatalf("Failed to initialize the bridge: %v", err)
	}

	h := network.NewHandler(dc.driver)
	h.ServeUnix("", pluginName)
}
