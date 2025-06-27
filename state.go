package main

import "sync"

// AppState holds the shared state for the application, including the
// configuration and a mutex to protect concurrent access to it.
type AppState struct {
	Config *Configuration
	Mutex  sync.RWMutex
}
