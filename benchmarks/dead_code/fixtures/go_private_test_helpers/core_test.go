package testhelpers

import "testing"

func TestRun(t *testing.T) { liveTestHelper(); core() }
func liveTestHelper() { testLeaf() }
func testLeaf() {}
func alpha() { beta() }
func beta() { alpha() }
func stale() {}
