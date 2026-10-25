package main

import (
	"context"

	"grantd/internal/proto"
)

// secretExists asks the daemon whether name is stored. There is deliberately no
// `grantd exists` verb (not in §8); import uses this to detect conflicts.
func secretExists(ctx context.Context, socketFlag, name string) (bool, error) {
	resp, err := simpleCall(ctx, socketFlag, &proto.Request{Op: proto.OpExists, Name: name})
	if err != nil {
		return false, err
	}
	var r proto.ExistsResult
	if err := decodeResult(resp, &r); err != nil {
		return false, err
	}
	return r.Exists, nil
}
