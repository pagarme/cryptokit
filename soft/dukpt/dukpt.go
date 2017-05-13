package dukpt

import (
	"bytes"
	"crypto/des"
	"encoding/binary"
	"unsafe"
)

type Ksn struct {
	Ksi     []byte
	Trsm    []byte
	Counter int
}

var (
	Reg3Mask     uint64 = 0x1FFFFF
	ShiftRegMask uint64 = 0x100000
	Reg8Mask     uint64 = 0xFFFFFFFFFFE00000
	KeyMask             = []byte{0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00}
	PekMask             = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF}
)

// This isn't official as there is no specification on how to build the KSI
// Aside from TC's 21 bits, the remaining 59 bits are opaque
// Here we assume the 10-5-5 scheme
func EncodeKsn(result []byte, ksn Ksn) {
	result[0] = ksn.Ksi[0]
	result[1] = ksn.Ksi[1]
	result[2] = ksn.Ksi[2]
	result[3] = ksn.Ksi[3]
	result[4] = ksn.Ksi[4]

	result[5] = ksn.Trsm[0]
	result[6] = ksn.Trsm[1]
	result[7] = ksn.Trsm[2] & 0xE0

	result[7] |= byte((ksn.Counter >> 16) & 0x1F)
	result[8] = byte((ksn.Counter >> 8) & 0xFF)
	result[9] = byte(ksn.Counter & 0xFF)
}

func DecodeKsn(ksn []byte) (result Ksn) {
	result = Ksn{
		Ksi:     make([]byte, 5),
		Trsm:    make([]byte, 3),
		Counter: 0,
	}

	result.Ksi[0] = ksn[0]
	result.Ksi[1] = ksn[1]
	result.Ksi[2] = ksn[2]
	result.Ksi[3] = ksn[3]
	result.Ksi[4] = ksn[4]

	result.Trsm[0] = ksn[5]
	result.Trsm[1] = ksn[6]
	result.Trsm[2] = ksn[7] & 0xE0

	result.Counter = int((uint64(ksn[9]) | (uint64(ksn[8]) << 8) | (uint64(ksn[7]&0x1F) << 16)))

	return
}

func CalculateKcv(key []byte) ([]byte, error) {
	kcv := make([]byte, 8)

	if err := tdesEncrypt(kcv, []byte{0, 0, 0, 0, 0, 0, 0, 0}, key); err != nil {
		return nil, err
	}

	return kcv[:3], nil
}

func ExtractKsnWithoutCounter(ksn, cleared []byte) {
	// Clear the KSN counter
	copy(cleared, ksn[:8])
	cleared[7] &= 0xE0
}

func DeriveIpekFromBdk(bdk []byte, ksn []byte) ([]byte, error) {
	cleared := make([]byte, 8)
	xored := make([]byte, 16)
	ipek := make([]byte, 16)

	ExtractKsnWithoutCounter(ksn, cleared)

	// Xor the BDK for the second key
	xorWords(xored, bdk, KeyMask)

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

	xorWords(key, key, PekMask)

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

	counter := decodeInt64(ksn[2:]) & Reg3Mask

	for shiftReg = ShiftRegMask; shiftReg != 0; shiftReg >>= 1 {
		if shiftReg&counter != 0 {
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
	xorWords(xored, key, KeyMask)

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

func decodeInt64(b []byte) (result uint64) {
	buffer := bytes.NewBuffer(b)
	binary.Read(buffer, binary.BigEndian, &result)
	return
}
