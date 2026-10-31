package oplock

import "sync"

type Lock struct {
	mutex  sync.Mutex
	held   bool
	holder string
	token  uint64
}

func New() *Lock {
	return &Lock{}
}

func (operationLock *Lock) TryAcquire(name string) (func(), bool) {
	operationLock.mutex.Lock()
	defer operationLock.mutex.Unlock()
	if operationLock.held {
		return nil, false
	}
	operationLock.held = true
	operationLock.holder = name
	operationLock.token++
	acquiredToken := operationLock.token
	return func() { operationLock.release(acquiredToken) }, true
}

func (operationLock *Lock) release(acquiredToken uint64) {
	operationLock.mutex.Lock()
	defer operationLock.mutex.Unlock()
	if operationLock.held && operationLock.token == acquiredToken {
		operationLock.held = false
		operationLock.holder = ""
	}
}

func (operationLock *Lock) Holder() string {
	operationLock.mutex.Lock()
	defer operationLock.mutex.Unlock()
	return operationLock.holder
}
