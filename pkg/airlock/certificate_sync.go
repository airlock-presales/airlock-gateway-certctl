package airlock

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ConfigurationTransaction owns one Airlock REST session with the active
// configuration loaded. Changes only become active when Commit succeeds.
type ConfigurationTransaction struct {
	client  *Client
	ctx     context.Context
	mu      sync.Mutex
	changed bool
	closed  bool
}

// StartConfigurationTransaction creates a REST session and loads the active
// Airlock Gateway configuration.
func (c *Client) StartConfigurationTransaction(ctx context.Context) (*ConfigurationTransaction, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	sessionClient, err := c.newSessionClient()
	if err != nil {
		return nil, err
	}
	if err := sessionClient.CreateSessionAndLoadActiveConfiguration(ctx); err != nil {
		return nil, err
	}
	return &ConfigurationTransaction{client: sessionClient, ctx: ctx}, nil
}

// Commit validates and activates all changes, then terminates the REST session.
// If nothing changed, it only terminates the session.
func (t *ConfigurationTransaction) Commit(activationComment string) error {
	return t.CommitWithOptions(activationComment, DefaultActivationOptions())
}

// CommitWithOptions validates and activates all changes using explicit
// appliance-side concurrency behavior, then terminates the REST session.
func (t *ConfigurationTransaction) CommitWithOptions(activationComment string, options ActivationOptions) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return errors.New("configuration transaction is closed")
	}
	if t.changed {
		messages, err := t.client.Validate(t.ctx)
		if err != nil {
			return t.finish(err)
		}
		if len(messages) != 0 {
			return t.finish(validationMessagesError(messages))
		}
		if err := t.client.ActivateConfigurationWithOptions(t.ctx, activationComment, options); err != nil {
			return t.finish(err)
		}
	}
	return t.finish(nil)
}

// Abort terminates the REST session without activating staged changes.
func (t *ConfigurationTransaction) Abort() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	return t.finish(nil)
}

func (t *ConfigurationTransaction) finish(operationErr error) error {
	terminationContext := t.ctx
	cancel := func() {}
	if t.ctx.Err() != nil {
		terminationContext, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	}
	defer cancel()
	terminateErr := t.client.TerminateSession(terminationContext)
	t.closed = true
	return errors.Join(operationErr, terminateErr)
}

func validationMessagesError(messages []ValidationMessage) error {
	details := make([]string, 0, len(messages))
	for _, message := range messages {
		detail := strings.TrimSpace(message.Detail)
		if detail == "" {
			detail = message.ID
		}
		details = append(details, detail)
	}
	return fmt.Errorf("configuration validation failed on Airlock Gateway: %s", strings.Join(details, "; "))
}
