package libsignalgo_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/beeper/libsignalgo"
)

func initializeSessions(t *testing.T, aliceStore, bobStore *InMemorySignalProtocolStore, bobAddress *libsignalgo.Address) {
	bobPreKey, err := libsignalgo.GeneratePrivateKey()
	assert.NoError(t, err)
	bobPreKeyPublicKey, err := bobPreKey.GetPublicKey()
	assert.NoError(t, err)

	bobSignedPreKey, err := libsignalgo.GeneratePrivateKey()
	assert.NoError(t, err)

	bobSignedPreKeyPublic, err := bobSignedPreKey.GetPublicKey()
	assert.NoError(t, err)
	bobSignedPreKeyPublicSerialized, err := bobSignedPreKeyPublic.Serialize()
	assert.NoError(t, err)

	bobIdentityKey, err := bobStore.GetIdentityKeyPair(nil)
	assert.NoError(t, err)
	bobSignedPreKeySignature, err := bobIdentityKey.GetPrivateKey().Sign(bobSignedPreKeyPublicSerialized)
	assert.NoError(t, err)

	var prekeyID uint32 = 4570
	var signedPreKeyID uint32 = 3006

	bobRegistrationID, err := bobStore.GetLocalRegistrationID(nil)
	assert.NoError(t, err)
	bobBundle, err := libsignalgo.NewPreKeyBundle(
		bobRegistrationID,
		9,
		prekeyID,
		bobPreKeyPublicKey,
		signedPreKeyID,
		bobSignedPreKeyPublic,
		bobSignedPreKeySignature,
		bobIdentityKey.GetPublicKey(),
	)
	assert.NoError(t, err)

	err = libsignalgo.ProcessPreKeyBundle(bobBundle, bobAddress, aliceStore, aliceStore, nil)
	assert.NoError(t, err)

	record, err := aliceStore.LoadSession(bobAddress, nil)
	assert.NoError(t, err)
	assert.NotNil(t, record)

	hasCurrentState, err := record.HasCurrentState()
	assert.NoError(t, err)
	assert.True(t, hasCurrentState)

	remoteRegistrationID, err := record.GetRemoteRegistrationID()
	assert.NoError(t, err)
	assert.Equal(t, bobRegistrationID, remoteRegistrationID)
}

func TestSessionCipher(t *testing.T) {
	// aliceAddress, err := libsignalgo.NewAddress("+14151111111", 1)
	// assert.NoError(t, err)
	bobAddress, err := libsignalgo.NewAddress("+14151111112", 1)
	assert.NoError(t, err)

	aliceStore := NewInMemorySignalProtocolStore()
	bobStore := NewInMemorySignalProtocolStore()

	initializeSessions(t, aliceStore, bobStore, bobAddress)
}
