package model

import (
	"time"
)

type User struct {
	FirstName    string    `json:"first_name" validate:"required,min=3,max=30"`
	LastName     string    `json:"last_name" validate:"required,min=3,max=30"`
	UserName     string    `json:"user_name" validate:"required,min=3,max=30"`
	Email        string    `json:"email" validate:"required,email"`
	Password     string    `json:"password" validate:"required,min=3"`
	Phone        string    `json:"phone" validate:"required,min=11,max=11"`
	AuthToken    string    `json:"auth_token"`
	RefreshToken string    `json:"refresh_token"`
	UserType     string    `json:"user_type" validate:"required,eq=ADMIN|eq=USER"`
	UserID       string    `json:"user_id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
