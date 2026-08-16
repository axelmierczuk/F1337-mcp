// Package fs implements FileService: read, write, edit, list, glob, and grep.
//
// Every path is resolved through the jail package before any syscall touches
// it.
//
// Implemented by milestone M1.
package fs
