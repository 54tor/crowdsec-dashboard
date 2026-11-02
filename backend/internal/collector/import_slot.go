package collector

import "context"

type importSlot struct {
	slots chan struct{}
	held  bool
}

func (slot *importSlot) acquire(ctx context.Context) error {
	select {
	case slot.slots <- struct{}{}:
		slot.held = true
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (slot *importSlot) release() {
	if slot.held {
		slot.held = false
		<-slot.slots
	}
}
