package configra

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/viper"
)

var (
	// ErrNotLoaded means Load has not installed an initial Snapshot.
	ErrNotLoaded = errors.New("Configra Viper Handler is not loaded")
	// ErrAlreadyLoaded means Load was called after an initial Snapshot was installed.
	ErrAlreadyLoaded = errors.New("Configra Viper Handler is already loaded")
	// ErrReloadRunning means a changed Snapshot arrived while the previous change callback was still running.
	ErrReloadRunning = errors.New("Configra Reload callback is already running")
	// ErrWatchRunning means Watch is already active for this Handler.
	ErrWatchRunning = errors.New("Configra Watch is already running")
)

// ChangeCallback observes a serialized transition between immutable Snapshots.
type ChangeCallback func(context.Context, *Snapshot, *Snapshot) error

// ViperHandlerOptions configures loading and watching one Config in one Environment.
type ViperHandlerOptions struct {
	Client        *Client
	Environment   string
	Config        string
	WatchInterval time.Duration
	OnChange      ChangeCallback
	OnError       func(error)
}

// ViperHandler maintains the last valid immutable Config Snapshot.
type ViperHandler struct {
	client        *Client
	environment   string
	config        string
	watchInterval time.Duration
	onChange      ChangeCallback
	onError       func(error)
	current       atomic.Pointer[Snapshot]
	reloadMu      sync.Mutex
	changeRunning atomic.Bool
	watching      atomic.Bool
	wait          func(context.Context, time.Duration) error
	jitter        func(time.Duration) time.Duration
}

// Snapshot is an immutable parsed Config and its exact revision evidence.
type Snapshot struct {
	values         *viper.Viper
	format         string
	configRevision uint64
	vaultRevisions map[string]uint64
	etag           string
}

// NewViperHandler validates options and creates an unloaded Handler.
func NewViperHandler(options ViperHandlerOptions) (*ViperHandler, error) {
	if options.Client == nil || !validResourceKey(options.Environment) || !validResourceKey(options.Config) {
		return nil, errors.New("Configra Client, Environment, and Config are required")
	}
	interval := options.WatchInterval
	if interval == 0 {
		interval = 30 * time.Second
	}
	if interval < 5*time.Second {
		return nil, errors.New("Configra Watch Interval must be at least 5 seconds")
	}
	return &ViperHandler{
		client:        options.Client,
		environment:   options.Environment,
		config:        options.Config,
		watchInterval: interval,
		onChange:      options.OnChange,
		onError:       options.OnError,
		wait:          waitContext,
		jitter: func(duration time.Duration) time.Duration {
			return time.Duration(float64(duration) * (0.9 + rand.Float64()*0.2))
		},
	}, nil
}

// Load fetches and installs the required initial Snapshot without invoking OnChange.
func (handler *ViperHandler) Load(ctx context.Context) (*Snapshot, error) {
	if handler == nil || ctx == nil {
		return nil, errors.New("Configra Viper Handler and Context are required")
	}
	handler.reloadMu.Lock()
	defer handler.reloadMu.Unlock()
	if handler.current.Load() != nil {
		return nil, ErrAlreadyLoaded
	}
	resolved, err := handler.client.ReadResolvedConfig(ctx, handler.environment, handler.config, "")
	if err != nil {
		return nil, err
	}
	snapshot, err := newSnapshot(resolved)
	if err != nil {
		return nil, err
	}
	handler.current.Store(snapshot)
	return snapshot, nil
}

// Reload checks for a newer Snapshot and reports whether one was installed.
func (handler *ViperHandler) Reload(ctx context.Context) (bool, error) {
	if handler == nil || ctx == nil {
		return false, errors.New("Configra Viper Handler and Context are required")
	}
	handler.reloadMu.Lock()
	changed, _, previous, current, err := handler.reloadLocked(ctx)
	handler.reloadMu.Unlock()
	if err == nil && changed {
		err = handler.notifyChange(ctx, previous, current)
	}
	return changed, err
}

// Current returns the installed Snapshot, or nil before Load succeeds.
func (handler *ViperHandler) Current() *Snapshot {
	if handler == nil {
		return nil
	}
	return handler.current.Load()
}

// Watch reloads until ctx is cancelled and retains the last valid Snapshot on failure.
func (handler *ViperHandler) Watch(ctx context.Context) error {
	if handler == nil || ctx == nil {
		return errors.New("Configra Viper Handler and Context are required")
	}
	if handler.current.Load() == nil {
		return ErrNotLoaded
	}
	if !handler.watching.CompareAndSwap(false, true) {
		return ErrWatchRunning
	}
	defer handler.watching.Store(false)
	delay := handler.watchInterval
	for {
		if err := handler.wait(ctx, handler.jitter(delay)); err != nil {
			return err
		}
		handler.reloadMu.Lock()
		changed, success, previous, current, err := handler.reloadLocked(ctx)
		handler.reloadMu.Unlock()
		if err == nil && changed {
			err = handler.notifyChange(ctx, previous, current)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil && handler.onError != nil {
			handler.onError(err)
		}
		if success {
			delay = handler.watchInterval
			continue
		}
		if delay >= 5*time.Minute/2 {
			delay = 5 * time.Minute
		} else {
			delay *= 2
		}
	}
}

func (handler *ViperHandler) reloadLocked(ctx context.Context) (changed, success bool, previous, current *Snapshot, resultErr error) {
	previous = handler.current.Load()
	if previous == nil {
		return false, false, nil, nil, ErrNotLoaded
	}
	resolved, err := handler.client.ReadResolvedConfig(ctx, handler.environment, handler.config, previous.etag)
	if errors.Is(err, ErrNotModified) {
		return false, true, nil, nil, nil
	}
	if err != nil {
		return false, false, nil, nil, err
	}
	current, err = newSnapshot(resolved)
	if err != nil {
		return false, false, nil, nil, err
	}
	if !handler.changeRunning.CompareAndSwap(false, true) {
		return false, false, nil, nil, ErrReloadRunning
	}
	handler.current.Store(current)
	return true, true, previous, current, nil
}

func (handler *ViperHandler) notifyChange(ctx context.Context, previous, current *Snapshot) error {
	defer handler.changeRunning.Store(false)
	if handler.onChange == nil {
		return nil
	}
	if err := handler.onChange(ctx, previous, current); err != nil {
		return fmt.Errorf("Configra Change Callback failed: %w", err)
	}
	return nil
}

func newSnapshot(resolved ResolvedConfig) (*Snapshot, error) {
	values := viper.New()
	values.SetConfigType(resolved.Format)
	if err := values.ReadConfig(strings.NewReader(resolved.Content)); err != nil {
		return nil, errors.New("invalid Configra configuration document")
	}
	return &Snapshot{
		values:         values,
		format:         resolved.Format,
		configRevision: resolved.ConfigRevision,
		vaultRevisions: maps.Clone(resolved.VaultRevisions),
		etag:           resolved.ETag,
	}, nil
}

// Unmarshal decodes the Snapshot into target using Viper.
func (snapshot *Snapshot) Unmarshal(target any, options ...viper.DecoderConfigOption) error {
	if snapshot == nil {
		return ErrNotLoaded
	}
	return snapshot.values.Unmarshal(target, options...)
}

// Format returns yaml or json.
func (snapshot *Snapshot) Format() string {
	if snapshot == nil {
		return ""
	}
	return snapshot.format
}

// ConfigRevision returns the immutable Config revision used by this Snapshot.
func (snapshot *Snapshot) ConfigRevision() uint64 {
	if snapshot == nil {
		return 0
	}
	return snapshot.configRevision
}

// VaultRevisions returns a copy keyed by namespace.item.
func (snapshot *Snapshot) VaultRevisions() map[string]uint64 {
	if snapshot == nil {
		return nil
	}
	return maps.Clone(snapshot.vaultRevisions)
}

// ETag returns the composite response validator for this Snapshot.
func (snapshot *Snapshot) ETag() string {
	if snapshot == nil {
		return ""
	}
	return snapshot.etag
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
