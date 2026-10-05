//go:build !linux

package app

import (
	"github.com/irondeploy/iron-gate/internal/engine"
	"github.com/irondeploy/iron-gate/internal/profile"
)

func defaultEngine(p *profile.Profile) (engine.Engine, error) { return engine.ForProfile(p) }
