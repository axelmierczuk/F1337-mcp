// Package platform isolates the OS-specific behaviour the agent depends on:
// process groups versus Windows job objects, PTY allocation, signal
// translation, and path normalisation.
//
// Implemented by milestone M1.
package platform
