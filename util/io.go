package util

import (
	"io"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
)

// MaybeClose will close the writer if its a Closer.
// Intended to be used with calls to defer.
func MaybeClose(writer io.Writer) {
	log := zapr.NewLogger(zap.L())
	if closer, isCloser := writer.(io.Closer); isCloser {
		err := closer.Close()

		if err != nil {
			log.Error(err, "Error closing writer")
		}
	}
}
