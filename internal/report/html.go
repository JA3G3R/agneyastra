package report

import (
	_ "embed"
	"html/template"
	"io"
	"os"
)

//go:embed template.html
var defaultHTMLTemplate string

// RenderHTML writes an HTML report to w. If templateFile is non-empty it is used
// instead of the embedded template (the embedded one requires no network, unlike
// the old download-on-startup behaviour).
func (r *Report) RenderHTML(w io.Writer, verbose bool, templateFile string) error {
	tmplStr := defaultHTMLTemplate
	if templateFile != "" {
		b, err := os.ReadFile(templateFile)
		if err != nil {
			return err
		}
		tmplStr = string(b)
	}
	tmpl, err := template.New("report").Parse(tmplStr)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, r.View(verbose))
}

// WriteHTMLFile renders the report to a file path.
func (r *Report) WriteHTMLFile(path string, verbose bool, templateFile string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return r.RenderHTML(f, verbose, templateFile)
}
