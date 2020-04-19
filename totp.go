package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

func main() {
	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Println(TOTP(string(data)))
}

func Key() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	key1 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
	key1 = strings.ToLower(key1)
	key2 := ""
	for i := 0; i < len(key1); i += 4 {
		if i != 0 {
			key2 += " "
		}
		key2 += key1[i : i+4]
	}
	return key2, nil
}

func CheckTOTP(key, code string) bool {
	code = strings.ReplaceAll(code, " ", "")
	counter := uint64(time.Now().Unix() / 30)
	if HOTP(key, counter-1) == code {
		return true
	}
	if HOTP(key, counter) == code {
		return true
	}
	if HOTP(key, counter+1) == code {
		return true
	}
	return false
}

func TOTP(key string) string {
	counter := uint64(time.Now().Unix() / 30)
	return HOTP(key, counter)
}

func HOTP(key string, counter uint64) string {
	key = strings.ReplaceAll(key, " ", "")
	key = strings.ReplaceAll(key, "\r", "")
	key = strings.ReplaceAll(key, "\n", "")
	key = strings.ReplaceAll(key, "\t", "")
	key = strings.ToUpper(key)
	data, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(key)
	if err != nil {
		panic(err)
	}
	h := hmac.New(sha1.New, data)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	if _, err := h.Write(buf); err != nil {
		panic(err)
	}
	sum := h.Sum(nil)
	index := sum[19] & 0x0f
	code := binary.BigEndian.Uint32(sum[index:])
	code &= 0x7fffffff
	code %= 1e6
	return fmt.Sprintf("%06d", code)
}
