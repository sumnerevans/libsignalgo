package libsignalgo_test

import (
	"crypto/rand"
	"math/big"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/beeper/libsignalgo"
)

type SenderKeyName struct {
	SenderName     string
	SenderDeviceID uint
	DistributionID uuid.UUID
}

type AddressKey struct {
	Name     string
	DeviceID uint
}

type InMemorySignalProtocolStore struct {
	privateKeys    *libsignalgo.IdentityKeyPair
	registrationID uint32

	identityKeyMap map[AddressKey]*libsignalgo.IdentityKey
	senderKeyMap   map[SenderKeyName]*libsignalgo.SenderKeyRecord
	sessionMap     map[AddressKey]*libsignalgo.SessionRecord
}

func NewInMemorySignalProtocolStore() *InMemorySignalProtocolStore {
	identityKeyPair, err := libsignalgo.GenerateIdentityKeyPair()
	if err != nil {
		panic(err)
	}

	registrationID, err := rand.Int(rand.Reader, big.NewInt(0x4000))
	if err != nil {
		panic(err)
	}

	return &InMemorySignalProtocolStore{
		privateKeys:    identityKeyPair,
		registrationID: uint32(registrationID.Uint64()),

		identityKeyMap: make(map[AddressKey]*libsignalgo.IdentityKey),
		senderKeyMap:   make(map[SenderKeyName]*libsignalgo.SenderKeyRecord),
		sessionMap:     make(map[AddressKey]*libsignalgo.SessionRecord),
	}
}

func (ps *InMemorySignalProtocolStore) LoadSession(address *libsignalgo.Address, context libsignalgo.StoreContext) (*libsignalgo.SessionRecord, error) {
	log.Debug().Msg("LoadSession called")
	name, err := address.Name()
	if err != nil {
		return nil, err
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return nil, err
	}
	return ps.sessionMap[AddressKey{name, deviceID}], nil
}

func (ps *InMemorySignalProtocolStore) StoreSession(address *libsignalgo.Address, record *libsignalgo.SessionRecord, context libsignalgo.StoreContext) error {
	log.Debug().Msg("StoreSession called")
	name, err := address.Name()
	if err != nil {
		return err
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return err
	}
	ps.sessionMap[AddressKey{name, deviceID}] = record
	return nil
}

func (ps *InMemorySignalProtocolStore) LoadSenderKey(sender libsignalgo.Address, distributionID uuid.UUID, context libsignalgo.StoreContext) (*libsignalgo.SenderKeyRecord, error) {
	log.Debug().Msg("LoadSenderKey called")
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
	log.Debug().Msg("StoreSenderKey called")
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

func (ps *InMemorySignalProtocolStore) GetIdentityKeyPair(context libsignalgo.StoreContext) (*libsignalgo.IdentityKeyPair, error) {
	log.Debug().Msg("GetIdentityKeyPair called")
	return ps.privateKeys, nil
}

func (ps *InMemorySignalProtocolStore) GetLocalRegistrationID(context libsignalgo.StoreContext) (uint32, error) {
	log.Debug().Msg("GetLocalRegistrationID called")
	return ps.registrationID, nil
}

func (ps *InMemorySignalProtocolStore) SaveIdentityKey(address *libsignalgo.Address, identityKey *libsignalgo.IdentityKey, context libsignalgo.StoreContext) error {
	log.Debug().Msg("SaveIdentityKey called")
	name, err := address.Name()
	if err != nil {
		return err
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return err
	}
	ps.identityKeyMap[AddressKey{name, deviceID}] = identityKey
	return err
}
func (ps *InMemorySignalProtocolStore) GetIdentityKey(address *libsignalgo.Address, context libsignalgo.StoreContext) (*libsignalgo.IdentityKey, error) {
	log.Debug().Msg("GetIdentityKey called")
	name, err := address.Name()
	if err != nil {
		return nil, err
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return nil, err
	}
	return ps.identityKeyMap[AddressKey{name, deviceID}], nil
}

func (ps *InMemorySignalProtocolStore) IsTrustedIdentity(address *libsignalgo.Address, identityKey *libsignalgo.IdentityKey, direction libsignalgo.SignalDirection, context libsignalgo.StoreContext) (bool, error) {
	log.Debug().Msg("IsTrustedIdentity called")
	name, err := address.Name()
	if err != nil {
		return false, err
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return false, err
	}
	if ik, ok := ps.identityKeyMap[AddressKey{name, deviceID}]; ok {
		return ik.Equal(identityKey)
	} else {
		log.Trace().Msg("Trusting on first use")
		return true, nil // Trust on first use
	}
}
