// Package admin is the admin UI: a SvelteKit app in this directory, built into build/ (npm run
// build) and embedded in the hub's binary. Without a build, build/ holds only .gitkeep and the hub
// says the UI isn't built.
package admin

import (
	"embed"
	"io/fs"
)

//go:embed all:build
var build embed.FS

// FS: the contents of build/
func FS() fs.FS {
	sub, err := fs.Sub(build, "build")
	if err != nil {
		panic(err)
	}
	return sub
}
