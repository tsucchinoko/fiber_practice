package models

type PasswordReset struct {
	Id    int
	Email string
	Token string
}
