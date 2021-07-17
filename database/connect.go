package database

import (
	"go-auth/models"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect() {
	connection, err := gorm.Open(mysql.Open("USER_NAME:PASSWORD@/DB_NAME"), &gorm.Config{})

	if err != nil {
		panic("Could not connect with database!")
	}

	DB = connection

	connection.AutoMigrate(&models.User{})
	connection.AutoMigrate(&models.PasswordReset{})
}
