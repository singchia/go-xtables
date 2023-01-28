package ebtables

import (
	"strconv"
	"strings"

	"github.com/singchia/go-xtables/internal/xlog"
)

type WatcherType int

func (wt WatcherType) Type() string {
	return "WatcherType"
}

func (wt WatcherType) Value() string {
	return strconv.Itoa(int(wt))
}

const (
	WatcherTypeLog WatcherType = iota
	WatcherTypeNFLog
	WatcherTypeULog
)

type Watcher interface {
	Type() WatcherType
	Short() string
	ShortArgs() []string
	Long() string
	LongArgs() []string
}

type baseWatcher struct {
	watcherType WatcherType
	child       Watcher
	invert      bool
}

func (bw baseWatcher) setChild(child Watcher) {
	bw.child = child
}

func (bw baseWatcher) Type() WatcherType {
	return bw.watcherType
}

func (bw baseWatcher) Short() string {
	if bw.child != nil {
		return bw.child.Short()
	}
	return ""
}

func (bw baseWatcher) ShortArgs() []string {
	if bw.child != nil {
		return bw.child.ShortArgs()
	}
	return nil
}

func (bw baseWatcher) Long() string {
	return bw.Short()
}

func (bw baseWatcher) LongArgs() []string {
	return bw.ShortArgs()
}

type OptionWatcherLog func(*WatcherLog)

// Log with the default logging options: log-level=info, log-prefix="",
// no ip logging, no arp logging. This option excludes others.
func WithWatcherLog() OptionWatcherLog {
	return func(watcher *WatcherLog) {
		watcher.Default = true
	}
}

type LogLevel xlog.LogLevel

const (
	LogLevelEMERG   = xlog.LogLevelEMERG
	LogLevelALERT   = xlog.LogLevelALERT
	LogLevelCRIT    = xlog.LogLevelCRIT
	LogLevelERR     = xlog.LogLevelERR
	LogLevelWARNING = xlog.LogLevelWARNING
	LogLevelNOTICE  = xlog.LogLevelNOTICE
	LogLevelINFO    = xlog.LogLevelINFO
	LogLevelDEBUG   = xlog.LogLevelDEBUG
)

// Defines the logging level.
func WithWatcherLogLevel(level LogLevel) OptionWatcherLog {
	return func(watcher *WatcherLog) {
		watcher.Level = level
	}
}

// Defines the prefix to be printed at the beginning of the line with
// the logging information.
func WithWatcherLogPrefix(prefix string) OptionWatcherLog {
	return func(watcher *WatcherLog) {
		watcher.Prefix = prefix
	}
}

// Will log the IP information when a frame made by the IP protocol
// matches the rule.
func WithWatcherLogIP() OptionWatcherLog {
	return func(watcher *WatcherLog) {
		watcher.IP = true
	}
}

// Will log the IPv6 information when a frame made by the IPv6 protocol
// matches the rule.
func WithWatcherLogIPv6() OptionWatcherLog {
	return func(watcher *WatcherLog) {
		watcher.IPv6 = true
	}
}

// Will log the (R)ARP information when a frame made by the (R)ARP protocols
// matches the rule.
func WithWatcherARP() OptionWatcherLog {
	return func(watcher *WatcherLog) {
		watcher.IPv6 = true
	}
}

func NewWatcherLog(opts ...OptionWatcherLog) (*WatcherLog, error) {
	watcher := &WatcherLog{
		baseWatcher: baseWatcher{
			watcherType: WatcherTypeLog,
		},
		Level: -1,
	}
	watcher.setChild(watcher)
	for _, opt := range opts {
		opt(watcher)
	}
	return watcher, nil
}

// The log watcher writes descriptive data about a frame to the syslog.
type WatcherLog struct {
	baseWatcher
	Default bool
	Level   LogLevel
	Prefix  string
	IP      bool
	IPv6    bool
	ARP     bool
}

func (watcher *WatcherLog) Short() string {
	return strings.Join(watcher.ShortArgs(), " ")
}

func (watcher *WatcherLog) ShortArgs() []string {
	args := make([]string, 0, 7)
	if watcher.Default == true {
		args = append(args, "--log")
		return args
	}
	if watcher.Level > -1 {
		args = append(args, "--log-level", strconv.Itoa(int(watcher.Level)))
	}
	if watcher.Prefix != "" {
		args = append(args, "--log-prefix", watcher.Prefix)
	}
	if watcher.IP {
		args = append(args, "--log-ip")
	}
	if watcher.IPv6 {
		args = append(args, "--log-ip6")
	}
	if watcher.ARP {
		args = append(args, "--log-arp")
	}
	return args
}

type OptionWatcherNFLog func(*WatcherNFLog)

// Log with the default logging options.
func WithWatcherNFLog() OptionWatcherNFLog {
	return func(watcher *WatcherNFLog) {
		watcher.Default = true
	}
}

// The netlink group(1 - 2^32-1) to which packets are(only applicable for
// nfnetlink_log). The default value is 1.
func WithWatcherNFLogGroup(group uint32) OptionWatcherNFLog {
	return func(watcher *WatcherNFLog) {
		watcher.Group = group
		watcher.HasGroup = true
	}
}

// A prefix string to include in the log message, up to 30 charactres long,
// useful for distinguishing messages in the logs.
func WithWatcherNFLogPrefix(prefix string) OptionWatcherNFLog {
	return func(watcher *WatcherNFLog) {
		watcher.Prefix = prefix
	}
}

// The number of bytes to be copied to userspace(only applicable for nfnetlink-
// _log). nfnetlink_log instances may specify their own range, this option
// overrides it.
func WithWatcherNFLogRange(rng uint64) OptionWatcherNFLog {
	return func(watcher *WatcherNFLog) {
		watcher.Range = rng
		watcher.HasRange = true
	}
}

// Number of packets to queue inside the kernel before sending them to userspace
// (only applicable for nfnetlink_log). Higher values result in less overhead
// per packet, but increase delay until the packets reach userspace.
func WithWatcherNFLogThreshold(size uint64) OptionWatcherNFLog {
	return func(watcher *WatcherNFLog) {
		watcher.Threshold = size
		watcher.HasThreshold = true
	}
}

func NewWatcherNFLog(opts ...OptionWatcherNFLog) (*WatcherNFLog, error) {
	watcher := &WatcherNFLog{
		baseWatcher: baseWatcher{
			watcherType: WatcherTypeNFLog,
		},
		Group: 1,
	}
	watcher.setChild(watcher)
	for _, opt := range opts {
		opt(watcher)
	}
	return watcher, nil
}

// The nflog watcher passes the packet to the loaded logging backend in
// order to log the packet. This is usually used in combination with nf-
// netlink_log as logging backend, which will multicast the packet through
// a netlink socket to the specified multicast group. One or more userspace
// processes may subscribe to the group to receive the packets.
type WatcherNFLog struct {
	baseWatcher
	Default      bool
	Group        uint32
	HasGroup     bool
	Prefix       string
	Range        uint64
	HasRange     bool
	Threshold    uint64
	HasThreshold bool
}

func (watcher *WatcherNFLog) Short() string {
	return strings.Join(watcher.ShortArgs(), " ")
}

func (watcher *WatcherNFLog) ShortArgs() []string {
	args := make([]string, 0, 8)
	if watcher.Default {
		args = append(args, "--nflog")
		return args
	}
	if watcher.HasGroup {
		args = append(args, "--nflog-group",
			strconv.FormatUint(uint64(watcher.Group), 10))
	}
	if watcher.Prefix != "" {
		args = append(args, "--nflog-prefix", watcher.Prefix)
	}
	if watcher.HasRange {
		args = append(args, "--nflog-range",
			strconv.FormatUint(watcher.Range, 10))
	}
	if watcher.HasThreshold {
		args = append(args, "--nflog-threshold",
			strconv.FormatUint(watcher.Threshold, 10))
	}
	return args
}

type OptionWatcherULog func(*WatcherULog)

// Use the default settings: ulog-prefix="", ulog-nlgroup=1, ulog-cprange=4096,
// ulog-qthreshold=1.
func WithWatcherULog() OptionWatcherULog {
	return func(watcher *WatcherULog) {
		watcher.Default = true
	}
}

// Defines the prefix included with the packets sent to userspace.
func WithWatcherPrefix(prefix string) OptionWatcherULog {
	return func(watcher *WatcherULog) {
		watcher.Prefix = prefix
	}
}

// Defines which netlink group number to use (a number from 1 to 32). Make sure
// the netlink group numbers used for the iptables ULOG target differ from those
// used for the ebtalbes ulog watcher. The default group number is 1.
func WithWatcherNLGroup(group int8) OptionWatcherULog {
	return func(watcher *WatcherULog) {
		watcher.NetlinkGroup = group
	}
}

// Defines the maximum copy range to userspace, for packets matching the rule. The
// default range is 0, which means the maximum copy range is given by nfbufsiz. A
// maximum copy range larger than 128*1024 is meaningless as the packets sent to
// userspace have an upper size limit of 128*1024.
func WithWatcherCPRange(rng int) OptionWatcherULog {
	return func(watcher *WatcherULog) {
		watcher.CopyRange = rng
	}
}

// Queue at most threshold number of packets before sending them to userspace with
// a netlink socket. Note that packets can be sent to userspace before the queue is
// full, this happens when the ulog kernel timer goes off (the frequency of this
// timer depends on flushtimeout).
func WithWatcherQThreshold(threshold int) OptionWatcherULog {
	return func(watcher *WatcherULog) {
		watcher.QueueThreshold = threshold
	}
}

func NewWatcherULog(opts ...OptionWatcherULog) (*WatcherULog, error) {
	watcher := &WatcherULog{
		baseWatcher: baseWatcher{
			watcherType: WatcherTypeULog,
		},
		NetlinkGroup:   1,
		CopyRange:      0,
		QueueThreshold: -1,
	}
	watcher.setChild(watcher)
	for _, opt := range opts {
		opt(watcher)
	}
	return watcher, nil
}

type WatcherULog struct {
	baseWatcher
	Default        bool
	Prefix         string
	NetlinkGroup   int8
	CopyRange      int
	QueueThreshold int
}

func (watcher *WatcherULog) Short() string {
	return strings.Join(watcher.ShortArgs(), " ")
}

func (watcher *WatcherULog) ShortArgs() []string {
	args := make([]string, 0, 8)
	if watcher.Default {
		args = append(args, "--ulog")
		return args
	}
	if watcher.NetlinkGroup > -1 {
		args = append(args, "--ulog-nlgroup",
			strconv.Itoa(int(watcher.NetlinkGroup)))
	}
	if watcher.Prefix != "" {
		args = append(args, "--ulog-prefix", watcher.Prefix)
	}
	if watcher.CopyRange > -1 {
		args = append(args, "--ulog-cprange",
			strconv.Itoa(watcher.CopyRange))
	}
	if watcher.QueueThreshold > -1 {
		args = append(args, "--ulog-qthreshold",
			strconv.Itoa(watcher.QueueThreshold))
	}
	return args
}
