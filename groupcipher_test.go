package libsignalgo_test

import (
	"testing"

	"github.com/beeper/libsignalgo"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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

func (ps *InMemorySignalProtocolStore) LoadSenderKey(sender libsignalgo.Address, distributionID uuid.UUID, context *libsignalgo.StoreContext) (*libsignalgo.SenderKeyRecord, error) {
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

func (ps *InMemorySignalProtocolStore) StoreSenderKey(sender libsignalgo.Address, distributionID uuid.UUID, record *libsignalgo.SenderKeyRecord, context *libsignalgo.StoreContext) error {
	name, err := sender.Name()
	if err != nil {
		return err
	}
	deviceID, err := sender.DeviceID()
	if err != nil {
		return err
	}
	cloned, err := record.Clone()
	if err != nil {
		return err
	}
	ps.senderKeyMap[SenderKeyName{name, deviceID, distributionID}] = cloned
	return nil
}

func TestGroupCipher(t *testing.T) {
	sender, err := libsignalgo.NewAddress("+14159999111", 4)
	assert.NoError(t, err)

	distributionID, err := uuid.Parse("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")
	assert.NoError(t, err)

	aliceStore := NewInMemorySignalProtocolStore()

	skdm, err := libsignalgo.NewSenderKeyDistributionMessage(sender, distributionID, aliceStore, libsignalgo.StoreContext{})
	assert.NoError(t, err)

	serialized, err := skdm.Serialize()
	assert.NoError(t, err)

	skdmReloaded, err := libsignalgo.DeserializeSenderKeyDistributionMessage(serialized)
	assert.NoError(t, err)

	aliceCiphertextMessage, err := libsignalgo.GroupEncrypt([]byte{1, 2, 3}, sender, distributionID, aliceStore, libsignalgo.StoreContext{})
	assert.NoError(t, err)

	aliceCiphertext, err := aliceCiphertextMessage.Serialize()
	assert.NoError(t, err)

	bobStore := NewInMemorySignalProtocolStore()
	err = skdmReloaded.Process(sender, bobStore, libsignalgo.StoreContext{})
	assert.NoError(t, err)

	bobPtext, err := libsignalgo.GroupDecrypt(aliceCiphertext, sender, bobStore, libsignalgo.StoreContext{})
	assert.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3}, bobPtext)
}
