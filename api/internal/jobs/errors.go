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
