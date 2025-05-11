package repositories

import "errors"

var ErrMultipleRecFound = errors.New("multiple record found")
var ErrRecNotFound = errors.New("record not found")
