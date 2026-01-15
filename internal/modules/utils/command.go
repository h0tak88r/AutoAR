package utils

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CommandRunner handles execution of external commands with logging and timeout
type CommandRunner struct {
	Timeout time.Duration
	Dir     string
	Env     []string
}

// NewCommandRunner creates a new CommandRunner with optional timeout
func NewCommandRunner(timeout time.Duration) *CommandRunner {
	return &CommandRunner{
		Timeout: timeout,
		Env:     os.Environ(),
	}
}

// Run executes a command and returns its output
func (c *CommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmdCtx := ctx
	var cancel context.CancelFunc
	
	if c.Timeout > 0 {
		cmdCtx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(cmdCtx, name, args...)
	cmd.Dir = c.Dir
	cmd.Env = c.Env

	cmdStr := fmt.Sprintf("%s %s", name, strings.Join(args, " "))
	Log.Debugf("Executing command: %s", cmdStr)

	start := time.Now()
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("command timed out after %v: %s", c.Timeout, cmdStr)
		}
		Log.Warnf("Command failed (%s): %v\nOutput: %s", duration, err, string(output))
		return output, err
	}

	Log.Debugf("Command finished successfully in %s", duration)
	return output, nil
}

// RunSilent executes a command without capturing output (returns stdout/stderr pipes if needed, or just runs it)
// This is a simple wrapper for cmd.Run() with logging
func (c *CommandRunner) RunSilent(ctx context.Context, name string, args ...string) error {
	cmdCtx := ctx
	var cancel context.CancelFunc
	
	if c.Timeout > 0 {
		cmdCtx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(cmdCtx, name, args...)
	cmd.Dir = c.Dir
	cmd.Env = c.Env
	
	// Inherit stdio for silent run if needed, or discard?
	// Usually "Silent" implies we don't want output in our app logs, 
	// but maybe we want it to go to /dev/null
	// existing code usually sets .Stdout = nil or similar.
	
	cmdStr := fmt.Sprintf("%s %s", name, strings.Join(args, " "))
	Log.Debugf("Executing command (silent): %s", cmdStr)

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("command timed out after %v: %s", c.Timeout, cmdStr)
		}
		Log.Warnf("Command failed (%s): %v", duration, err)
		return err
	}

	Log.Debugf("Command finished successfully in %s", duration)
	return nil
}
