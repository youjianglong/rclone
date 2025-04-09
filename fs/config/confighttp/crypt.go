package confighttp

import (
	"crypto/aes"
	"crypto/cipher"
)

var EncryptKey = []byte{0x44, 0x4C, 0x67, 0x70, 0x6B, 0x46, 0x4D, 0x43, 0x31, 0x4D, 0x6D, 0x4F, 0x79, 0x79, 0x41, 0x78}

func padZero(data []byte, size int) []byte {
	if len(data) >= size {
		return data[:size]
	}
	padLen := size - len(data)
	for i := 0; i < padLen; i++ {
		data = append(data, 0)
	}
	return data
}

func SymmetricDecrypt(data []byte, key, iv []byte) ([]byte, error) {
	// 使用aes-128-cfb解密
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBDecrypter(block, padZero(iv, block.BlockSize()))
	stream.XORKeyStream(data, data)
	return data, nil
}

func SymmetricEncrypt(data []byte, key, iv []byte) ([]byte, error) {
	// 使用aes-128-cfb加密
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, padZero(iv, block.BlockSize()))
	stream.XORKeyStream(data, data)
	return data, nil
}
