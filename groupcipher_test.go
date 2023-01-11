package libsignalgo_test

import (
	"fmt"
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
	fmt.Printf("%v %v %v===%v\n", name, deviceID, distributionID, ps.senderKeyMap[SenderKeyName{name, deviceID, distributionID}])
	if ps.senderKeyMap[SenderKeyName{name, deviceID, distributionID}] != nil {
		sk, err := ps.senderKeyMap[SenderKeyName{name, deviceID, distributionID}].Serialize()
		fmt.Printf("=>=> %v %v\n", sk, err)
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
	fmt.Printf("store %v %v %v %v\n", name, deviceID, distributionID, record)
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

	distributionID := uuid.New()

	aliceStore := NewInMemorySignalProtocolStore()

	skdm, err := libsignalgo.NewSenderKeyDistributionMessage(sender, distributionID, aliceStore, libsignalgo.StoreContext{})
	assert.NoError(t, err)

	serialized, err := skdm.Serialize()
	assert.NoError(t, err)

	skdmReloaded, err := libsignalgo.DeserializeSenderKeyDistributionMessage(serialized)
	assert.NoError(t, err)

	assert.NotNil(t, skdmReloaded) // TODO Remove

	fmt.Printf("ALICE %v\n", aliceStore)

	aliceCiphertextMessage, err := libsignalgo.GroupEncrypt([]byte{1, 2, 3}, sender, distributionID, aliceStore, libsignalgo.StoreContext{})
	assert.NoError(t, err)

	aliceCiphertext, err := aliceCiphertextMessage.Serialize()
	assert.NoError(t, err)

	assert.Equal(t, []byte{}, aliceCiphertext) // TODO Remove

	bobStore := NewInMemorySignalProtocolStore()
	err = skdmReloaded.Process(sender, bobStore, libsignalgo.StoreContext{})
	assert.NoError(t, err)

	bobPtext, err := libsignalgo.GroupDecrypt(aliceCiphertext, sender, bobStore, libsignalgo.StoreContext{})
	assert.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3}, bobPtext)

	//     let a_ctext = try! groupEncrypt([1, 2, 3], from: sender, distributionId: distribution_id, store: a_store, context: NullContext()).serialize()

	//     let b_store = InMemorySignalProtocolStore()
	//     try! processSenderKeyDistributionMessage(skdm_r,
	//                                              from: sender,
	//                                              store: b_store,
	//                                              context: NullContext())
	//     let b_ptext = try! groupDecrypt(a_ctext, from: sender, store: b_store, context: NullContext())

	//     XCTAssertEqual(b_ptext, [1, 2, 3])
	// }
}
