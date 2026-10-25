package service

import (
	"context"
	"errors"
	"os/exec"
)

func execCommand(ctx context.Context, name string, args ...string) (Result, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err == nil {
		return Result{Output: string(out)}, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return Result{Output: string(out), ExitCode: ee.ExitCode()}, nil
	}
	return Result{}, err
}
