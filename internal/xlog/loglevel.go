package xlog

type LogLevel int8

const (
	LogLevelEMERG   LogLevel = 0 /* system is unusable */
	LogLevelALERT   LogLevel = 1 /* action must be taken immediately */
	LogLevelCRIT    LogLevel = 2 /* critical conditions */
	LogLevelERR     LogLevel = 3 /* error conditions */
	LogLevelWARNING LogLevel = 4 /* warning conditions */
	LogLevelNOTICE  LogLevel = 5 /* normal but significant condition */
	LogLevelINFO    LogLevel = 6 /* informational */
	LogLevelDEBUG   LogLevel = 7 /* debug-level messages */
)
