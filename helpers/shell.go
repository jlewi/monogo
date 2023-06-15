package helpers

import (
	"strings"

	"github.com/go-cmd/cmd"
	"github.com/go-logr/logr"
)

// StreamCmdToLogs streams the output of a command to the logs
func StreamCmdToLogs(c *cmd.Cmd, log logr.Logger) {
	// Print STDOUT and STDERR lines streaming from Cmd
	// N.B looks like this may not get used and may just be a vestige of copied coe
	doneChan := make(chan struct{})
	go func() {
		defer close(doneChan)
		// Done when both channels have been closed
		// https://dave.cheney.net/2013/04/30/curious-channels
		for c.Stdout != nil || c.Stderr != nil {
			select {
			case line, open := <-c.Stdout:
				if !open {
					c.Stdout = nil
					continue
				}
				log.Info(line)
			case line, open := <-c.Stderr:
				if !open {
					c.Stderr = nil
					continue
				}
				log.Info(line)
			}
		}
	}()
}

// CmdToString generates a string representation of a command
func CmdToString(c cmd.Cmd) string {
	all := make([]string, 0, len(c.Args)+1)
	all = append(all, c.Name)
	all = append(all, c.Args...)
	return strings.Join(all, " ")
}
