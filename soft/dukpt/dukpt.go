package dukpt

import (
	"unsafe"
	"bytes"
	"crypto/des"
	"encoding/binary"
)

var (
	REG3_MASK      uint64 = 0x1FFFFF
	SHIFT_REG_MASK uint64 = 0x100000
	REG8_MASK      uint64 = 0xFFFFFFFFFFE00000
	KEY_MASK              = []byte{0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00}
	PEK_MASK              = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF}
)

func DeriveIpekFromBdk(bdk []byte, ksn []byte) ([]byte, error) {
	cleared := make([]byte, 8)
	xored := make([]byte, 16)
	ipek := make([]byte, 16)

	// Clear the KSN counter
	copy(cleared, ksn[:8])
	cleared[7] &= 0xE0

	// Xor the BDK for the second key
	xorWords(xored, bdk, KEY_MASK)

	if err := tdesEncrypt(ipek[0:8], cleared, bdk); err != nil {
		return nil, err
	}

	if err := tdesEncrypt(ipek[8:16], cleared, xored); err != nil {
		return nil, err
	}

	return ipek, nil
}

func DerivePekFromIpek(ipek []byte, ksn []byte) ([]byte, error) {
	key := make([]byte, 16)

	if err := deriveKey(key, ipek, ksn); err != nil {
		return nil, err
	}

	xorWords(key, key, PEK_MASK)

	return key, nil
}

func DerivePekFromBdk(bdk []byte, ksn []byte) ([]byte, error) {
	ipek, err := DeriveIpekFromBdk(bdk, ksn)

	if err != nil {
		return nil, err
	}

	return DerivePekFromIpek(ipek, ksn)
}

func deriveKey(dst, ipek, ksn []byte) error {
	var shiftReg uint64

	copy(dst, ipek)

	reg8 := make([]byte, 8)
	copy(reg8, ksn[2:])
	reg8[7] = 0
	reg8[6] = 0
	reg8[5] &= 0xE0

	counter := retrieveInt64(ksn[2:]) & REG3_MASK

	for shiftReg = SHIFT_REG_MASK; shiftReg != 0; shiftReg >>= 1 {
		if shiftReg & counter != 0 {
			ptr := *(*[8]byte)(unsafe.Pointer(&shiftReg))

			reg8[5] |= ptr[2]
			reg8[6] |= ptr[1]
			reg8[7] |= ptr[0]

			if err := keygen(dst, dst, reg8); err != nil {
				return err
			}
		}
	}

	return nil
}

func keygen(dst, key, ksn []byte) error {
	xored := make([]byte, 16)
	temp := make([]byte, 16)

	// Xor the key for the second key
	xorWords(xored, key, KEY_MASK)

	if err := encryptRegister(temp[0:8], xored, ksn); err != nil {
		return err
	}

	if err := encryptRegister(temp[8:16], key, ksn); err != nil {
		return err
	}

	copy(dst, temp)

	return nil
}

func encryptRegister(dst, curkey, reg8 []byte) error {
	message := make([]byte, 8)

	left := curkey[0:8]
	right := curkey[8:16]

	xorWords(message, right, reg8)

	if err := desEncrypt(message, message, left); err != nil {
		return err
	}

	xorWords(dst, right, message)

	return nil
}

func buildTdesKey(key []byte) []byte {
	var finalKey []byte

	if len(key) == 24 {
		finalKey = key
	} else if len(key) == 16 {
		finalKey = make([]byte, 24)
		copy(finalKey, key)
		copy(finalKey[16:], key[:8])
	}

	return finalKey
}

func tdesEncrypt(dst, data, key []byte) error {
	block, err := des.NewTripleDESCipher(buildTdesKey(key))

	if err != nil {
		return err
	}

	block.Encrypt(dst, data)

	return nil
}

func desEncrypt(dst, data, key []byte) error {
	block, err := des.NewCipher(key)

	if err != nil {
		return err
	}

	block.Encrypt(dst, data)

	return nil
}

func retrieveInt64(b []byte) (result uint64) {
	buffer := bytes.NewBuffer(b)
	binary.Read(buffer, binary.BigEndian, &result)
	return
}
