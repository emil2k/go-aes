package log

import (
	"log"
)

// LeveledLogger allows for the setting of logs for info, debug, and error.
type LeveledLogger interface {
	SetErrorLog(errorLog *log.Logger)
	SetInfoLog(infoLog *log.Logger)
	SetDebugLog(debugLog *log.Logger)
}
