package bridge

import (
	"encoding/json"
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/datastore"
)

const bridgePrefix = "bridge"

func (d *driver) storeUpdate(kvObject datastore.KVObject) error {
	if d.store == nil {
		logrus.Warnf("bridge store not initialized. kv object %s is not added to the store", datastore.Key(kvObject.Key()...))
		return nil
	}

	if err := d.store.PutObjectAtomic(kvObject); err != nil {
		return fmt.Errorf("failed to update bridge store for object type %T: %v", kvObject, err)
	}

	return nil
}

func (d *driver) storeDelete(kvObject datastore.KVObject) error {
	if d.store == nil {
		logrus.Debugf("bridge store not initialized. kv object %s is not deleted from store", datastore.Key(kvObject.Key()...))
		return nil
	}

retry:
	if err := d.store.DeleteObjectAtomic(kvObject); err != nil {
		if err == datastore.ErrKeyModified {
			if err := d.store.GetObject(datastore.Key(kvObject.Key()...), kvObject); err != nil {
				return fmt.Errorf("could not update the kvobject to latest when trying to delete: %v", err)
			}
			goto retry
		}
		return err
	}

	return nil
}

func (ncfg *networkConfiguration) Key() []string {
	return []string{bridgePrefix, ncfg.ID}
}

func (ncfg *networkConfiguration) KeyPrefix() []string {
	return []string{bridgePrefix}
}

func (ncfg *networkConfiguration) Value() []byte {
	b, err := json.Marshal(ncfg)
	if err != nil {
		return nil
	}
	return b
}

func (ncfg *networkConfiguration) SetValue(value []byte) error {
	return json.Unmarshal(value, ncfg)
}

func (ncfg *networkConfiguration) Index() uint64 {
	return ncfg.dbIndex
}

func (ncfg *networkConfiguration) SetIndex(index uint64) {
	ncfg.dbIndex = index
	ncfg.dbExists = true
}

func (ncfg *networkConfiguration) Exists() bool {
	return ncfg.dbExists
}

func (ncfg *networkConfiguration) Skip() bool {
	return ncfg.DefaultBridge
}

func (ncfg *networkConfiguration) DataScope() string {
	return datastore.LocalScope
}
