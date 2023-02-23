package libsignalgo_test

import (
	"testing"

	"github.com/beeper/libsignalgo"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// From ZKGroupTests.swift
func TestZKGroup(t *testing.T) {
	setupLogging()

	TEST_ARRAY_16, err := uuid.FromBytes([]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f})
	assert.NoError(t, err)

	/*
		TEST_ARRAY_16_1, err := uuid.FromBytes([]byte{
			0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
			0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73})
		assert.NoError(t, err)
	*/

	TEST_ARRAY_32 := [32]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}

	TEST_ARRAY_32_1 := [32]byte{
		0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
		0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73,
		0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b,
		0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83}

	TEST_ARRAY_32_2 := [32]byte{
		0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
		0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
		0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
		0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7}

	/*
		TEST_ARRAY_32_3 := [32]byte{
			1, 2, 3, 4, 5, 6, 7, 8,
			9, 10, 11, 12, 13, 14, 15, 16,
			17, 18, 19, 20, 21, 22, 23, 24,
			25, 26, 27, 28, 29, 30, 31, 32}

		TEST_ARRAY_32_4 := [32]byte{
			2, 3, 4, 5, 6, 7, 8, 9,
			10, 11, 12, 13, 14, 15, 16, 17,
			18, 19, 20, 21, 22, 23, 24, 25,
			26, 27, 28, 29, 30, 31, 32, 33}
	*/

	TEST_ARRAY_32_5 := [32]byte{
		0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
		0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22}

	// From ZKGroupTests.swift:testAuthIntegration
	ok := t.Run("testAuthIntegration", func(t *testing.T) {
		uuid := TEST_ARRAY_16
		redemptionTime := uint32(123456)

		// Generate keys (client's are per-group, server's are not)
		// ---

		// SERVER
		serverSecretParams, err := libsignalgo.GenerateServerSecretParamsWithRandomness(TEST_ARRAY_32)
		assert.NoError(t, err)
		serverPublicParams, err := serverSecretParams.GetPublicParams()
		assert.NoError(t, err)
		serverZkAuth := libsignalgo.NewServerZkAuthOperations(serverSecretParams)

		// CLIENT
		masterKey := libsignalgo.GroupMasterKey(TEST_ARRAY_32_1)
		groupSecretParams, err := libsignalgo.DeriveGroupSecretParamsFromMasterKey(masterKey)
		assert.NoError(t, err)

		groupSecretParamsMasterKey, err := groupSecretParams.GetMasterKey()
		assert.NoError(t, err)
		assert.Equal(t, groupSecretParamsMasterKey, masterKey)

		/*groupPublicParams*/
		_, err = groupSecretParams.GetPublicParams()
		assert.NoError(t, err)

		// SERVER
		// Issue credential
		authCredentialResponse, err := serverZkAuth.IssueAuthCredentialWithRandomness(TEST_ARRAY_32_2, uuid, redemptionTime)
		assert.NoError(t, err)

		// CLIENT
		// Receive credential
		clientZkAuthCipher := libsignalgo.NewClientZkAuthOperations(serverPublicParams)
		clientZkGroupCipher := libsignalgo.NewClientZkGroupCipher(groupSecretParams)
		authCredential, err := clientZkAuthCipher.ReceiveAuthCredential(uuid, redemptionTime, authCredentialResponse)
		assert.NoError(t, err)

		// Create and decrypt user entry
		uuidCiphertext, err := clientZkGroupCipher.EncryptUuid(uuid)
		plaintext, err := clientZkGroupCipher.DecryptUuid(uuidCiphertext)
		assert.Equal(t, uuid, plaintext)

		// Create presentation
		/*presentation*/
		_, err = clientZkAuthCipher.CreateAuthCredentialPresentationWithRandomness(TEST_ARRAY_32_5, groupSecretParams, authCredential)
		assert.NoError(t, err)
	})
	require.True(t, ok)
}
