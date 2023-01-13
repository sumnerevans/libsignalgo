package libsignalgo_test

import (
	"github.com/google/uuid"

	"github.com/beeper/libsignalgo"
)

type SenderKeyName struct {
	SenderName     string
	SenderDeviceID uint
	DistributionID uuid.UUID
}

type InMemorySignalProtocolStore struct {
	senderKeyMap map[SenderKeyName]*libsignalgo.SenderKeyRecord
}

func NewInMemorySignalProtocolStore() *InMemorySignalProtocolStore {
	return &InMemorySignalProtocolStore{
		senderKeyMap: make(map[SenderKeyName]*libsignalgo.SenderKeyRecord),
	}
}

func (ps *InMemorySignalProtocolStore) LoadSenderKey(sender libsignalgo.Address, distributionID uuid.UUID, context libsignalgo.StoreContext) (*libsignalgo.SenderKeyRecord, error) {
	name, err := sender.Name()
	if err != nil {
		return nil, err
	}
	deviceID, err := sender.DeviceID()
	if err != nil {
		return nil, err
	}
	return ps.senderKeyMap[SenderKeyName{name, deviceID, distributionID}], nil
}

func (ps *InMemorySignalProtocolStore) StoreSenderKey(sender libsignalgo.Address, distributionID uuid.UUID, record *libsignalgo.SenderKeyRecord, context libsignalgo.StoreContext) error {
	name, err := sender.Name()
	if err != nil {
		return err
	}
	deviceID, err := sender.DeviceID()
	if err != nil {
		return err
	}
	ps.senderKeyMap[SenderKeyName{name, deviceID, distributionID}] = record
	return nil
}
