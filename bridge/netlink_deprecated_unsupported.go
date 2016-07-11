// +build !linux

package bridge

import (
	"errors"
)

func ioctlCreateBridge(name string, setMacAddr bool) error {
	return errors.New("not implemented")
}
