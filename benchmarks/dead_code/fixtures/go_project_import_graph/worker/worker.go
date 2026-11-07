package worker

import "example.net/workflow/provider"

func Factory() func() { provider.Touch(); return callback }
func callback() {}
func alpha() { beta() }
func beta() { alpha() }
func orphan() {}
