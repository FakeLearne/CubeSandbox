package runtime

import (
	"context"
	"errors"
	"testing"

	"github.com/tencentcloud/CubeSandbox/CubeNet/cubevs"
)

func TestInvalidateSandboxConnectionsBumpsActiveTAP(t *testing.T) {
	adapter := &fakeCubeVSAdapter{bumpOldVersion: 7, bumpNewVersion: 8}
	controller := &NetworkController{
		locks:         NewSandboxLocks(),
		states:        map[string]*managedState{"sandbox": {persistedState: persistedState{SandboxID: "sandbox", TapIfIndex: 42}}},
		cubevsAdapter: adapter,
		version:       3,
	}

	oldVersion, newVersion, err := controller.InvalidateSandboxConnections(context.Background(), "sandbox")
	if err != nil {
		t.Fatal(err)
	}
	if oldVersion != 7 || newVersion != 8 {
		t.Fatalf("versions=(%d,%d), want (7,8)", oldVersion, newVersion)
	}
	if len(adapter.bumpTAPDeviceCalls) != 1 || adapter.bumpTAPDeviceCalls[0] != 42 {
		t.Fatalf("bump calls=%v, want [42]", adapter.bumpTAPDeviceCalls)
	}
	if controller.version != 3 {
		t.Fatalf("controller allocator version=%d, want unchanged 3", controller.version)
	}
}

func TestCheckSandboxConnectionsRequiresCubeVSMetadata(t *testing.T) {
	adapter := &fakeCubeVSAdapter{
		getTAPDeviceByIndex: map[uint32]*cubevs.TAPDevice{
			42: {Ifindex: 42},
		},
	}
	controller := &NetworkController{
		locks:         NewSandboxLocks(),
		states:        map[string]*managedState{"sandbox": {persistedState: persistedState{SandboxID: "sandbox", TapIfIndex: 42}}},
		cubevsAdapter: adapter,
	}
	if err := controller.CheckSandboxConnections(context.Background(), "sandbox"); err != nil {
		t.Fatal(err)
	}

	delete(adapter.getTAPDeviceByIndex, 42)
	if err := controller.CheckSandboxConnections(context.Background(), "sandbox"); err == nil {
		t.Fatal("missing CubeVS metadata returned nil error")
	}
}

func TestInvalidateSandboxConnectionsRequiresActiveState(t *testing.T) {
	controller := &NetworkController{
		locks:         NewSandboxLocks(),
		states:        make(map[string]*managedState),
		cubevsAdapter: &fakeCubeVSAdapter{},
	}

	if _, _, err := controller.InvalidateSandboxConnections(context.Background(), "missing"); err == nil {
		t.Fatal("missing active state returned nil error")
	}
}

func TestInvalidateSandboxConnectionsPropagatesCubeVSError(t *testing.T) {
	bumpErr := errors.New("map update failed")
	adapter := &fakeCubeVSAdapter{bumpOldVersion: 7, bumpTAPDeviceErr: bumpErr}
	controller := &NetworkController{
		locks:         NewSandboxLocks(),
		states:        map[string]*managedState{"sandbox": {persistedState: persistedState{SandboxID: "sandbox", TapIfIndex: 42}}},
		cubevsAdapter: adapter,
	}

	oldVersion, newVersion, err := controller.InvalidateSandboxConnections(context.Background(), "sandbox")
	if !errors.Is(err, bumpErr) {
		t.Fatalf("error=%v, want %v", err, bumpErr)
	}
	if oldVersion != 7 || newVersion != 0 {
		t.Fatalf("versions=(%d,%d), want (7,0)", oldVersion, newVersion)
	}
	if _, pending := controller.pendingConnectionInvalidations["sandbox"]; !pending {
		t.Fatal("failed invalidation was not queued for maintenance")
	}

	adapter.bumpTAPDeviceErr = nil
	adapter.bumpNewVersion = 8
	controller.retryPendingConnectionInvalidations()
	if _, pending := controller.pendingConnectionInvalidations["sandbox"]; pending {
		t.Fatal("successful maintenance retry did not clear pending invalidation")
	}
}
