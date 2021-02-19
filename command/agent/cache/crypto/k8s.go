package crypto

import (
	"io/ioutil"

	"github.com/hashicorp/vault/helper/dhutil"
)

type kubeKeyManager struct{}

func (k *kubeKeyManager) New(saPath string) (*kubeEncryptionKey, error) {
	var key kubeEncryptionKey
	jwt, err := ioutil.ReadFile(saPath)
	if err != nil {
		return &key, err
	}
	key.aad = jwt

	_, key.privateKey, err = dhutil.GeneratePublicPrivateKey()
	if err != nil {
		return &key, err
	}

	return &key, nil
}

func (k *kubeKeyManager) Load(privateKey []byte, saPath string) (*kubeEncryptionKey, error) {
	jwt, err := ioutil.ReadFile(saPath)
	if err != nil {
		return &kubeEncryptionKey{}, err
	}

	return &kubeEncryptionKey{
		aad:        jwt,
		privateKey: privateKey,
	}, nil
}

func (k *kubeKeyManager) Renew() error {
	return nil
}

type kubeEncryptionKey struct {
	aad        []byte
	privateKey []byte
}

func (k *kubeEncryptionKey) Encrypt(plaintext []byte) ([]byte, []byte, error) {
	return dhutil.EncryptAES(k.privateKey, plaintext, k.aad)
}

func (k *kubeEncryptionKey) Decrypt(ciphertext, nonce []byte) ([]byte, error) {
	return dhutil.DecryptAES(k.privateKey, ciphertext, nonce, k.aad)
}

/*
package main

func main() {

	// **Kubernetes**
	// New workflow
	var k8sKey crypto.kubeKeyManager
	key, err := k8sKey.NewKey(saPath)
	if err != nil {
		...
	}

	err = key.Store("path/to/store")
	if err != nil {
		...
	}

	ciphertext, nonce, err := key.Encrypt([]byte{"myvalue"})
	if err != nil {
		...
	}

	// Restore workflow
	var k8sKey crypto.kubeKeyManager
	key, err := k8sKey.Load(privateKey, saPath)
	if err != nil {
		...
	}

    plaintext, err := key.Decrypt(ciphertext, nonce)
	if err != nil {
		...
	}
*/

/*
package main

func main() {
	// **Response Wrap**
	var responseWrappedKey crypto.responseWrappedKeyManager
	key, err := responseWrappedKey.NewKey("")
	if err != nil {
		...
	}

	err = key.Store("path/to/store")
	if err != nil {
		...
	}

	err = key.Renew()
	if err != nil {
		...
	}

	ciphertext, nonce, err := key.Encrypt([]byte{"myvalue"})
	if err != nil {
		...
	}

	// Restore workflow
	var responseWrappedKey crypto.responseWrappedKeyManager
	key, err := responseWrappedKey.Load(privateKey, saPath)
	if err != nil {
		...
	}

    plaintext, err := key.Decrypt(ciphertext, nonce)
	if err != nil {
		...
	}

}
*/
