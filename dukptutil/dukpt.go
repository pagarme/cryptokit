package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/SSSaaS/sssa-golang"
	"github.com/buger/goterm"
	"github.com/pagarme/cryptokit/soft/dukpt"
	"github.com/tucnak/climax"
)

func main() {
	app := climax.New("dukpt")

	app.AddCommand(climax.Command{
		Name:   "bdk_kcv",
		Brief:  "Calculates the BDK or BDK part KCV",
		Handle: derivedBdkKcv,
		Flags: []climax.Flag{
			{
				Name:  "use-sss",
				Short: "s",
			},
		},
	})

	app.AddCommand(climax.Command{
		Name:   "derived_bdk_kcv",
		Brief:  "Calculates the derived BDK KCV",
		Handle: derivedBdkKcv,
		Flags: []climax.Flag{
			{
				Name:  "use-sss",
				Short: "s",
			},
		},
	})

	app.AddCommand(climax.Command{
		Name:   "derived_bdk_split_sss",
		Brief:  "Splits the BDK using Shamir Secret Sharing",
		Handle: splitBdkSss,
		Flags: []climax.Flag{
			{
				Name:  "use-sss",
				Short: "s",
			},
		},
	})

	app.AddCommand(climax.Command{
		Name:   "derived_bdk_split_xor",
		Brief:  "Splits the BDK using XOR, outputing their KCVs",
		Handle: splitBdkXor,
		Flags: []climax.Flag{
			{
				Name:  "use-sss",
				Short: "s",
			},
		},
	})

	app.Run()
}

func splitBdkSss(ctx climax.Context) int {
	min := 0
	shares := 0

	bdk, err := deriveBdk(ctx.Is("use-sss"))

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return -1
	}

	fmt.Printf("Enter the number of shares: ")
	fmt.Scanf("%d\n", &shares)

	fmt.Printf("Enter the minimum number of shares: ")
	fmt.Scanf("%d\n", &min)

	fmt.Printf("\n")

	secrets := sssa.Create(min, shares, hex.EncodeToString(bdk))

	for i, v := range secrets {
		clearScreen()

		fmt.Printf("Secret #%d: %s\n\n", i, v)
		fmt.Printf("Write it down as press enter to continue to the next part.\n")

		fmt.Scanf("\n")
	}

	clearScreen()

	kcv, err := dukpt.CalculateKcv(bdk)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return -1
	}

	kcvStr := hex.EncodeToString(kcv)

	fmt.Printf("BDK KCV: %s\n", kcvStr)

	return 0
}

func splitBdkXor(ctx climax.Context) int {
	shares := 0

	bdk, err := deriveBdk(ctx.Is("use-sss"))

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return -1
	}

	fmt.Printf("Enter the number of shares: ")
	fmt.Scanf("%d\n", &shares)

	secrets := make([][]byte, shares)
	final := make([]byte, 16)

	for i := 0; i < len(secrets)-1; i++ {
		s := make([]byte, 16)

		if _, err := rand.Read(s); err != nil {
			fmt.Printf("Error: %v\n", err)
			return -1
		}

		xorArray(final, final, s)
		secrets[i] = s
	}

	xorArray(final, final, bdk)
	secrets[len(secrets)-1] = final

	fmt.Printf("\n")

	for i, v := range secrets {
		kcv, err := dukpt.CalculateKcv(v)

		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return -1
		}

		secretStr := hex.EncodeToString(v)
		kcvStr := hex.EncodeToString(kcv)

		clearScreen()

		fmt.Printf("Secret #%d: %s (KCV = %s)\n", i, secretStr, kcvStr)
		fmt.Printf("Write it down as press enter to continue to the next part.\n")

		fmt.Scanf("\n")
	}

	clearScreen()

	kcv, err := dukpt.CalculateKcv(bdk)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return -1
	}

	kcvStr := hex.EncodeToString(kcv)

	fmt.Printf("BDK KCV: %s\n", kcvStr)

	return 0
}

func derivedBdkKcv(ctx climax.Context) int {
	bdk, err := deriveBdk(ctx.Is("use-sss"))

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return -1
	}

	kcv, err := dukpt.CalculateKcv(bdk)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return -1
	}

	kcvStr := hex.EncodeToString(kcv)

	fmt.Printf("BDK KCV: %s\n", kcvStr)

	return 0
}

func deriveBdk(useSss bool) ([]byte, error) {
	if useSss {
		count := 1
		secrets := make([]string, 0)

		for true {
			secret := ""

			fmt.Printf("Enter key part #%d (empty to end): ", count)
			fmt.Scanf("%s\n", &secret)

			if secret == "" {
				break
			}

			secrets = append(secrets, secret)
			count++
		}

		return hex.DecodeString(sssa.Combine(secrets))
	}

	count := 1
	bdk := make([]byte, 16)

	for true {
		fmt.Printf("Enter key part #%d (empty to end): ", count)
		part, err := askHex()

		if err != nil {
			return nil, err
		}

		if len(part) == 0 {
			break
		} else if len(part) != 16 {
			return nil, errors.New("Key tool small")
		}

		fmt.Printf("Enter key part #%d KCV: ", count)
		kcv, err := askHex()

		if err != nil {
			return nil, err
		}

		computedKcv, err := dukpt.CalculateKcv(part)

		if !compareKcv(kcv, computedKcv) {
			return nil, errors.New("Keys doesn't match")
		}

		if err != nil {
			return nil, err
		}

		xorArray(bdk, bdk, part)

		count++
	}

	return bdk, nil
}

func askHex() ([]byte, error) {
	str := ""

	fmt.Scanf("%s\n", &str)

	if str == "" {
		return []byte{}, nil
	}

	return hex.DecodeString(str)
}

func compareKcv(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}

	return true
}

func xorArray(result, a, b []byte) {
	for i, v := range a {
		result[i] = v ^ b[i]
	}
}

func clearScreen() {
	goterm.Clear()
	goterm.MoveCursor(1, 1)
	goterm.Flush()
}
