// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"time"

	CubeLog "github.com/tencentcloud/CubeSandbox/cubelog"
)

func (s *NetworkController) activeSandboxTAPIfindex(sandboxID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.states[sandboxID]
	if !ok || state == nil {
		return 0, fmt.Errorf("active network state not found for sandbox %q", sandboxID)
	}
	if state.TapIfIndex <= 0 {
		return 0, fmt.Errorf(
			"active network state for sandbox %q has invalid TAP ifindex %d",
			sandboxID,
			state.TapIfIndex,
		)
	}
	return state.TapIfIndex, nil
}

// CheckSandboxConnections verifies that rollback can later invalidate the
// active sandbox without changing its current connection generation.
func (s *NetworkController) CheckSandboxConnections(ctx context.Context, sandboxID string) error {
	if sandboxID == "" {
		return fmt.Errorf("sandbox ID is empty")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	unlock := func() {}
	if s.locks != nil {
		unlock = s.locks.Lock(sandboxID)
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	ifindex, err := s.activeSandboxTAPIfindex(sandboxID)
	if err != nil {
		return err
	}
	if _, err := s.cubevsAdapter.GetTAPDevice(uint32(ifindex)); err != nil {
		return fmt.Errorf(
			"check CubeVS metadata for sandbox %q TAP ifindex %d: %w",
			sandboxID,
			ifindex,
			err,
		)
	}
	return nil
}

// InvalidateSandboxConnections advances the CubeVS connection generation for
// an active sandbox. It shares the lifecycle lock used by EnsureNetwork and
// ReleaseNetwork so an ifindex cannot be invalidated after being reassigned.
func (s *NetworkController) InvalidateSandboxConnections(
	ctx context.Context,
	sandboxID string,
) (oldVersion uint32, newVersion uint32, err error) {
	if sandboxID == "" {
		return 0, 0, fmt.Errorf("sandbox ID is empty")
	}

	if err := ctx.Err(); err != nil {
		s.enqueueConnectionInvalidation(sandboxID)
		return 0, 0, err
	}

	unlock := func() {}
	if s.locks != nil {
		unlock = s.locks.Lock(sandboxID)
	}
	defer unlock()

	if err := ctx.Err(); err != nil {
		s.enqueueConnectionInvalidation(sandboxID)
		return 0, 0, err
	}

	ifindex, err := s.activeSandboxTAPIfindex(sandboxID)
	if err != nil {
		return 0, 0, err
	}

	start := time.Now()
	oldVersion, newVersion, err = s.cubevsAdapter.BumpTAPDeviceVersion(uint32(ifindex))
	if err != nil {
		s.enqueueConnectionInvalidation(sandboxID)
		return oldVersion, 0, fmt.Errorf(
			"invalidate CubeVS connections for sandbox %q TAP ifindex %d: %w",
			sandboxID, ifindex, err,
		)
	}
	s.clearConnectionInvalidation(sandboxID)

	CubeLog.WithContext(ctx).Infof(
		"network runtime invalidated sandbox connections: sandbox_id=%s tap_ifindex=%d old_version=%d new_version=%d latency=%s",
		sandboxID, ifindex, oldVersion, newVersion, time.Since(start),
	)
	return oldVersion, newVersion, nil
}

func (s *NetworkController) enqueueConnectionInvalidation(sandboxID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingConnectionInvalidations == nil {
		s.pendingConnectionInvalidations = make(map[string]struct{})
	}
	s.pendingConnectionInvalidations[sandboxID] = struct{}{}
}

func (s *NetworkController) clearConnectionInvalidation(sandboxID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendingConnectionInvalidations, sandboxID)
}

func (s *NetworkController) retryPendingConnectionInvalidations() {
	s.mu.Lock()
	sandboxIDs := make([]string, 0, len(s.pendingConnectionInvalidations))
	for sandboxID := range s.pendingConnectionInvalidations {
		sandboxIDs = append(sandboxIDs, sandboxID)
	}
	s.mu.Unlock()

	for _, sandboxID := range sandboxIDs {
		unlock := func() {}
		if s.locks != nil {
			unlock = s.locks.Lock(sandboxID)
		}

		s.mu.Lock()
		_, pending := s.pendingConnectionInvalidations[sandboxID]
		s.mu.Unlock()
		if !pending {
			unlock()
			continue
		}

		ifindex, err := s.activeSandboxTAPIfindex(sandboxID)
		if err != nil {
			s.clearConnectionInvalidation(sandboxID)
			unlock()
			CubeLog.WithContext(context.Background()).Warnf(
				"dropping pending connection invalidation without active network: sandbox_id=%s err=%v",
				sandboxID,
				err,
			)
			continue
		}

		oldVersion, newVersion, err := s.cubevsAdapter.BumpTAPDeviceVersion(uint32(ifindex))
		if err == nil {
			s.clearConnectionInvalidation(sandboxID)
		}
		unlock()
		if err != nil {
			CubeLog.WithContext(context.Background()).Warnf(
				"network maintenance failed to invalidate sandbox connections: sandbox_id=%s tap_ifindex=%d err=%v",
				sandboxID,
				ifindex,
				err,
			)
			continue
		}
		CubeLog.WithContext(context.Background()).Infof(
			"network maintenance invalidated sandbox connections: sandbox_id=%s tap_ifindex=%d old_version=%d new_version=%d",
			sandboxID,
			ifindex,
			oldVersion,
			newVersion,
		)
	}
}
