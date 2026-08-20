package cubevs

import (
	"testing"
	"time"
	"unsafe"
)

func TestSessionLayoutMatchesNatSessionWithoutTypeReuse(t *testing.T) {
	var got session
	var legacy natSession
	if unsafe.Sizeof(got) != 64 {
		t.Fatalf("session size=%d, want 64", unsafe.Sizeof(got))
	}
	if unsafe.Sizeof(got) != unsafe.Sizeof(legacy) {
		t.Fatalf("session size=%d, natSession size=%d", unsafe.Sizeof(got), unsafe.Sizeof(legacy))
	}
	if unsafe.Offsetof(got.State) != unsafe.Offsetof(legacy.State) ||
		unsafe.Offsetof(got.ActiveClose) != unsafe.Offsetof(legacy.ActiveClose) {
		t.Fatalf("TCP state fields diverged: session=%#v natSession=%#v", got, legacy)
	}
}

func TestOriginalSessionDispositionDeletesStaleGeneration(t *testing.T) {
	now := uint64((4 * time.Hour).Nanoseconds())
	key := sessionKey{Version: 7}
	value := session{
		AccessTime: now - uint64(time.Minute.Nanoseconds()),
		State:      uint8(tcpCTEstablished),
	}

	deleteEntry, expired, stale := originalSessionDisposition(now, &key, &value, 8, false)
	if !deleteEntry || expired || !stale {
		t.Fatalf("disposition=(delete=%t expired=%t stale=%t), want (true,false,true)",
			deleteEntry, expired, stale)
	}
}

func TestOriginalSessionDispositionKeepsCurrentEstablished(t *testing.T) {
	now := uint64((4 * time.Hour).Nanoseconds())
	key := sessionKey{Version: 8}
	value := session{
		AccessTime: now - uint64(time.Minute.Nanoseconds()),
		State:      uint8(tcpCTEstablished),
	}

	deleteEntry, expired, stale := originalSessionDisposition(now, &key, &value, 8, false)
	if deleteEntry || expired || stale {
		t.Fatalf("disposition=(delete=%t expired=%t stale=%t), want all false",
			deleteEntry, expired, stale)
	}
}

func TestOriginalSessionDispositionDeletesOrphan(t *testing.T) {
	key := sessionKey{Version: 8}
	value := session{State: uint8(tcpCTEstablished)}
	deleteEntry, _, _ := originalSessionDisposition(1, &key, &value, 0, true)
	if !deleteEntry {
		t.Fatal("orphan original session was retained")
	}
}
