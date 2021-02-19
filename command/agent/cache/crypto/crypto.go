package crypto

type Encrypter interface {
	Encrypt([]byte) ([]byte, []byte, error)
	Decrypt([]byte) ([]byte, error)
}

type KeyManager interface {
	GetKey() ([]byte, error)
	Store() func()
}
