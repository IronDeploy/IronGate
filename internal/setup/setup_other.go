//go:build !linux

// Package setup: o helper só existe no Linux (Windows e macOS entram nas Fases 2 e 3).
package setup

import "errors"

func Install(string) error { return errors.New("o helper só existe no Linux") }
func Uninstall() error     { return errors.New("o helper só existe no Linux") }

func ExportUnits(string, string) error { return errors.New("o helper só existe no Linux") }
