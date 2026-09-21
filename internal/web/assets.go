// assets.go embeds every byte the Control Center serves: one HTML
// page, one stylesheet, one script, one logo. Zero external references
// — no CDN, no fonts, no analytics (security model #4, pinned by the
// external-URL scan test: the only tolerated http strings are w3.org
// XML namespaces inside the SVG).

package web

import "embed"

// embeddedAssets carries the whole UI at compile time. The directive
// embeds the entire assets/ directory, so the scan test walks exactly
// what a build can serve.
//
//go:embed assets
var embeddedAssets embed.FS

// staticAsset is one /static/* file with its fixed Content-Type.
type staticAsset struct {
	body        []byte
	contentType string
}

var (
	// indexHTML is the / body.
	indexHTML []byte
	// staticAssets maps the /static/<name> path tail to its bytes; the
	// fixed key set doubles as the complete static route table.
	staticAssets map[string]staticAsset
)

func init() {
	indexHTML = mustAsset("index.html")
	staticAssets = map[string]staticAsset{
		"styles.css": {mustAsset("styles.css"), "text/css; charset=utf-8"},
		"app.js":     {mustAsset("app.js"), "text/javascript; charset=utf-8"},
		"logo.svg":   {mustAsset("logo.svg"), "image/svg+xml"},
	}
}

// mustAsset panics on a mismatched embed set — a programmer error that
// cannot be reached without the file present (the //go:embed directive
// fails compilation first) and that any route test catches immediately.
func mustAsset(name string) []byte {
	b, err := embeddedAssets.ReadFile("assets/" + name)
	if err != nil {
		panic("web: embedded asset " + name + ": " + err.Error())
	}
	return b
}
