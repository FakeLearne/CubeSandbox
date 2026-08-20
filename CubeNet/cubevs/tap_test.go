package cubevs

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeTapMetadataMap struct {
	entries   map[uint32]uint32
	lookupErr error
	deleteErr error
}

type fakeTapVersionMap struct {
	meta      mvmMetadata
	lookupErr error
	updateErr error
	flags     ebpf.MapUpdateFlags
}

func (m *fakeTapVersionMap) Lookup(_ interface{}, valueOut interface{}) error {
	if m.lookupErr != nil {
		return m.lookupErr
	}
	*valueOut.(*mvmMetadata) = m.meta
	return nil
}

func (m *fakeTapVersionMap) Update(_, value interface{}, flags ebpf.MapUpdateFlags) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.meta = *value.(*mvmMetadata)
	m.flags = flags
	return nil
}

func (m *fakeTapMetadataMap) Lookup(key, valueOut interface{}) error {
	if m.lookupErr != nil {
		return m.lookupErr
	}
	value, ok := m.entries[*key.(*uint32)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*uint32) = value
	return nil
}

func (m *fakeTapMetadataMap) Delete(key interface{}) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	typedKey := *key.(*uint32)
	if _, ok := m.entries[typedKey]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.entries, typedKey)
	return nil
}

func TestDeleteTAPDeviceMetadataEntriesDeletesMatchingReverseEntry(t *testing.T) {
	const (
		ifindex = uint32(12)
		mvmIP   = uint32(0x0a000002)
	)
	ifindexMap := &fakeTapMetadataMap{entries: map[uint32]uint32{ifindex: 0}}
	ipMap := &fakeTapMetadataMap{entries: map[uint32]uint32{mvmIP: ifindex}}

	if err := deleteTAPDeviceMetadataEntries(ifindexMap, ipMap, ifindex, mvmIP); err != nil {
		t.Fatal(err)
	}
	if len(ifindexMap.entries) != 0 || len(ipMap.entries) != 0 {
		t.Fatalf("matching metadata was not fully deleted: ifindex=%#v ip=%#v", ifindexMap.entries, ipMap.entries)
	}
}

func TestDeleteTAPDeviceMetadataEntriesPreservesReusedIP(t *testing.T) {
	const (
		oldIfindex = uint32(12)
		newIfindex = uint32(13)
		mvmIP      = uint32(0x0a000002)
	)
	ifindexMap := &fakeTapMetadataMap{entries: map[uint32]uint32{oldIfindex: 0}}
	ipMap := &fakeTapMetadataMap{entries: map[uint32]uint32{mvmIP: newIfindex}}

	if err := deleteTAPDeviceMetadataEntries(ifindexMap, ipMap, oldIfindex, mvmIP); err != nil {
		t.Fatal(err)
	}
	if _, ok := ifindexMap.entries[oldIfindex]; ok {
		t.Fatal("old ifindex metadata was not deleted")
	}
	if got := ipMap.entries[mvmIP]; got != newIfindex {
		t.Fatalf("reused IP mapping changed to ifindex %d, want %d", got, newIfindex)
	}
}

func TestDeleteTAPDeviceMetadataEntriesTreatsMissingReverseEntryAsClean(t *testing.T) {
	const (
		ifindex = uint32(12)
		mvmIP   = uint32(0x0a000002)
	)
	ifindexMap := &fakeTapMetadataMap{entries: map[uint32]uint32{ifindex: 0}}
	ipMap := &fakeTapMetadataMap{entries: make(map[uint32]uint32)}

	if err := deleteTAPDeviceMetadataEntries(ifindexMap, ipMap, ifindex, mvmIP); err != nil {
		t.Fatal(err)
	}
	if _, ok := ifindexMap.entries[ifindex]; ok {
		t.Fatal("ifindex metadata was not deleted")
	}
}

func TestDeleteTAPDeviceMetadataEntriesLookupErrorDoesNotPartiallyDelete(t *testing.T) {
	const (
		ifindex = uint32(12)
		mvmIP   = uint32(0x0a000002)
	)
	lookupErr := errors.New("lookup failed")
	ifindexMap := &fakeTapMetadataMap{entries: map[uint32]uint32{ifindex: 0}}
	ipMap := &fakeTapMetadataMap{
		entries:   make(map[uint32]uint32),
		lookupErr: lookupErr,
	}

	err := deleteTAPDeviceMetadataEntries(ifindexMap, ipMap, ifindex, mvmIP)
	if !errors.Is(err, lookupErr) {
		t.Fatalf("error = %v, want %v", err, lookupErr)
	}
	if _, ok := ifindexMap.entries[ifindex]; !ok {
		t.Fatal("ifindex metadata was deleted after reverse lookup failed")
	}
}

func TestBumpTAPDeviceVersionPreservesMetadata(t *testing.T) {
	m := &fakeTapVersionMap{meta: mvmMetadata{
		IP:             0x01020304,
		Version:        41,
		UUID:           stringToByteArray("sandbox"),
		DNSPolicyFlags: 3,
		Reserved:       [55]uint8{1, 2, 3},
	}}
	before := m.meta

	oldVersion, newVersion, err := bumpTAPDeviceVersion(m, 12)
	if err != nil {
		t.Fatal(err)
	}
	if oldVersion != 41 || newVersion != 42 {
		t.Fatalf("versions=(%d,%d), want (41,42)", oldVersion, newVersion)
	}
	if m.meta.Version != 42 {
		t.Fatalf("stored version=%d, want 42", m.meta.Version)
	}
	before.Version = 42
	if m.meta != before {
		t.Fatalf("metadata changed beyond version: got=%#v want=%#v", m.meta, before)
	}
	if m.flags != ebpf.UpdateExist {
		t.Fatalf("update flags=%v, want UpdateExist", m.flags)
	}
}

func TestBumpTAPDeviceVersionSkipsZeroOnWrap(t *testing.T) {
	m := &fakeTapVersionMap{meta: mvmMetadata{Version: ^uint32(0)}}
	oldVersion, newVersion, err := bumpTAPDeviceVersion(m, 12)
	if err != nil {
		t.Fatal(err)
	}
	if oldVersion != ^uint32(0) || newVersion != 1 || m.meta.Version != 1 {
		t.Fatalf("versions=(%d,%d) stored=%d, want (%d,1,1)",
			oldVersion, newVersion, m.meta.Version, ^uint32(0))
	}
}

func TestBumpTAPDeviceVersionPropagatesLookupError(t *testing.T) {
	lookupErr := errors.New("lookup failed")
	_, _, err := bumpTAPDeviceVersion(&fakeTapVersionMap{lookupErr: lookupErr}, 12)
	if !errors.Is(err, lookupErr) {
		t.Fatalf("error=%v, want %v", err, lookupErr)
	}
}
