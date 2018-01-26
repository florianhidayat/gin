// Copyright 2014 Manu Martinez-Almeida.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package gin

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"crypto/aes"
	"crypto/cipher"
	"reflect"
	"os"
)

const (
	noWritten     = -1
	defaultStatus = 200
)

type ResponseWriter interface {
	http.ResponseWriter
	http.Hijacker
	http.Flusher
	http.CloseNotifier

	// Returns the HTTP response status code of the current request.
	Status() int

	// Returns the number of bytes already written into the response customhttp body.
	// See Written()
	Size() int

	// Writes the string into the response body.
	WriteString(string) (int, error)

	// Returns true if the response body was already written.
	Written() bool

	// Forces to write the customhttp header (status code + headers).
	WriteHeaderNow()

	// Enables/disables encryption.
	EnableEncryption(bool)

	// Enables/disables encryption.
	EncryptionEnabled() bool

	//sets key for encryption.
	SetKey([]byte)

	//sets IV for encryption.
	SetIV([]byte)

	//sets start index in file (in byte order)
	SetStartIndex(uint64)

	//attaches file, used if seeking is needed.
	AttachFile(*os.File)
}

type responseWriter struct {
	http.ResponseWriter
	size   int
	status int
	encryptionParams
}

type encryptionParams struct {
	key []byte
	iv []byte
	enableEncryption bool
	file *os.File
	startIndex uint64
}

var _ ResponseWriter = &responseWriter{}

func (w *responseWriter) reset(writer http.ResponseWriter) {
	w.ResponseWriter = writer
	w.size = noWritten
	w.status = defaultStatus
	w.enableEncryption = false
}

func (w *responseWriter) WriteHeader(code int) {
	if code > 0 && w.status != code {
		if w.Written() {
			debugPrint("[WARNING] Headers were already written. Wanted to override status code %d with %d", w.status, code)
		}
		w.status = code
	}
}

func (w *responseWriter) WriteHeaderNow() {
	if !w.Written() {
		w.size = 0
		w.ResponseWriter.WriteHeader(w.status)
	}
}

func (w *responseWriter) Write(data []byte) (n int, err error) {
	//println("data length is", len(data), " bytes")
	w.WriteHeaderNow()
	//n, err = w.ResponseWriter.Write(data)
	if w.enableEncryption {
		var nextIv []byte
		var encrypted []byte

		//only prepend once
		if w.size == 0 {
			prependedData, offset, _ := w.prependIfNeeded(data)
			//println("data length becomes", len(prependedData), "offset is", offset)

			encrypted, nextIv = encrypt(w.key, w.iv, prependedData)
			n, err = w.ResponseWriter.Write(encrypted[offset:])
			//data = prependedData[offset:]
			n -= int(offset)
		} else {
			encrypted, nextIv = encrypt(w.key, w.iv, data)
			n, err = w.ResponseWriter.Write(encrypted)
			//println("n is:", n)
		}

		w.iv = nextIv
	} else {
		n, err = w.ResponseWriter.Write(data)
	}
	//println("data length is now", len(data), "size before:", w.size, "n is:", n)
	w.size += n
	//println("next IV is", hex.EncodeToString(w.iv), "size now is", w.size)
	//println("size becomes", w.size, " bytes")
	return
}

func (w *responseWriter) WriteString(s string) (n int, err error) {
	w.WriteHeaderNow()
	n, err = io.WriteString(w.ResponseWriter, s)
	w.size += n
	return
}

func (w *responseWriter) Status() int {
	return w.status
}

func (w *responseWriter) Size() int {
	return w.size
}

func (w *responseWriter) Written() bool {
	return w.size != noWritten
}

// Hijack implements the customhttp.Hijacker interface.
func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.size < 0 {
		w.size = 0
	}
	return w.ResponseWriter.(http.Hijacker).Hijack()
}

// CloseNotify implements the customhttp.CloseNotify interface.
func (w *responseWriter) CloseNotify() <-chan bool {
	return w.ResponseWriter.(http.CloseNotifier).CloseNotify()
}

// Flush implements the customhttp.Flush interface.
func (w *responseWriter) Flush() {
	w.ResponseWriter.(http.Flusher).Flush()
}

func (w *responseWriter) EnableEncryption(enabled bool) {
	w.enableEncryption = enabled
}

func (w *responseWriter) EncryptionEnabled() bool {
	return w.enableEncryption
}

func (w *responseWriter) SetKey(key []byte) {
	w.key = key
}

func (w *responseWriter) SetIV(iv []byte) {
	w.iv = iv
}

func (w *responseWriter) SetStartIndex(index uint64) {
	w.startIndex = index
}

func (w *responseWriter) AttachFile(file *os.File) {
	w.file = file
}

func (w *responseWriter) prependIfNeeded(data []byte) (prependedData []byte, prependedBytes uint64, err error) {
	prependedBytes = w.startIndex % 16
	if prependedBytes > 0 {
		bytesToPrepend := make([]byte, prependedBytes)
		_, err := w.file.ReadAt(bytesToPrepend, int64(w.startIndex -prependedBytes))
		if err != nil {
			return nil,0, err
		}

		prependedData = append(bytesToPrepend, data...)
		return prependedData, prependedBytes, err
	} else {
		return data, prependedBytes, err
	}
}

// encrypt using AES/CTR/NoPadding
func encrypt(key []byte, iv []byte, data []byte) ([]byte, []byte) {
	// key := []byte(keyText)
	//plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	//plainTextWithPadding := padding.AddPkcs7(plaintext, aes.BlockSize)
	//iv := ciphertext[:aes.BlockSize]
	//if _, err := io.ReadFull(rand.Reader, iv); err != nil {
	//	panic(err)
	//}
	encrypted := make([]byte, len(data))

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(encrypted, data)

	v := reflect.ValueOf(stream).Elem()
	//println("ctr value is:", hex.EncodeToString(v.FieldByName("ctr").Bytes()))
	//stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return encrypted, v.FieldByName("ctr").Bytes()
	//return hex.EncodeToString(ciphertext)
}


// decrypt from hex to decrypted string
func decrypt(key []byte, iv []byte, data []byte) ([]byte, []byte) {
	//ciphertext, _ := hex.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(data) < aes.BlockSize {
		panic("ciphertext too short")
	}
	//iv := ciphertext[:aes.BlockSize]
	//ciphertext = ciphertext[aes.BlockSize:]

	//stream := cipher.NewCFBDecrypter(block, iv)
	stream := cipher.NewCTR(block, iv)
	origData := make([]byte, len(data))

	// XORKeyStream can work in-place if the two arguments are the same.
	//stream.CryptBlocks(origData, ciphertext)
	stream.XORKeyStream(origData, data)
	v := reflect.ValueOf(stream).Elem()
	//origData = padding.RemovePkcs7(origData, aes.BlockSize)

	return origData, v.FieldByName("ctr").Bytes()
}