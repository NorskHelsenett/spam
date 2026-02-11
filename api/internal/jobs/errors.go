package jobs

import "errors"

type nonRetryableError struct {
	err error
}

func (e nonRetryableError) Error() string {
	return e.err.Error()
}

func (e nonRetryableError) Unwrap() error {
	return e.err
}

// NonRetryable wraps an error to signal the worker this failure should not be retried.
func NonRetryable(err error) error {
	if err == nil {
		return nil
	}
	return nonRetryableError{err: err}
}

// IsNonRetryable reports whether the error has been marked as non-retryable.
func IsNonRetryable(err error) bool {
	if err == nil {
		return false
	}
	var target nonRetryableError
	ok := errors.As(err, &target)
	return ok
}

type providerUnavailableError struct {
	err error
}

func (e providerUnavailableError) Error() string {
	return e.err.Error()
}

func (e providerUnavailableError) Unwrap() error {
	return e.err
}

// ProviderUnavailable wraps an error to signal the worker that the provider
// is temporarily down. The job should be retried without counting the attempt.
func ProviderUnavailable(err error) error {
	if err == nil {
		return nil
	}
	return providerUnavailableError{err: err}
}

// IsProviderUnavailable reports whether the error indicates a provider is temporarily unavailable.
func IsProviderUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var target providerUnavailableError
	return errors.As(err, &target)
}
