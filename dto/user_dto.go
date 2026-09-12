package dto

import (
	"errors"
	"strings"
)

// UserUpdateDTO intentionally excludes ID, tenant ID, and role.
type UserUpdateDTO struct {
	FirstName *string `json:"first_name,omitempty"`
	Bio       *string `json:"bio,omitempty"`
}

func (u UserUpdateDTO) Validate() error {
	if u.FirstName == nil && u.Bio == nil {
		return errors.New("provide first_name or bio")
	}
	if u.FirstName != nil && (len(strings.TrimSpace(*u.FirstName)) == 0 || len(*u.FirstName) > 100) {
		return errors.New("first_name must contain 1 to 100 characters")
	}
	if u.Bio != nil && len(*u.Bio) > 500 {
		return errors.New("bio must not exceed 500 characters")
	}
	return nil
}
