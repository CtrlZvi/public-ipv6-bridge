package main

import (
	"github.com/CtrlZvi/public-ipv6-bridge/bridge"
	"github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/network"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	pluginName = "public-ipv6-bridge"
)

var (
	debug = kingpin.Flag("debug", "enable debug logging").Default("false").Bool()
)

func main() {
	kingpin.Parse()
	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
	d := bridge.NewDriver()
	logrus.Debugf("Starting public IPv6 bridge Docker network plugin")
	h := network.NewHandler(d)
	h.ServeUnix("", pluginName)
}
