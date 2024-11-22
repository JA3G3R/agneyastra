package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"os"
	"time"
)

func toJson(v interface{}) string {
    b, _ := json.MarshalIndent(v, "", "  ")
    return string(b)
}

func (report *Report) GenerateHTMLReport( filename string, templateFile string) error {
	// HTML template string
    // read html from template file
    htmlTemplate, err := ioutil.ReadFile(templateFile)
    if err != nil {
        return fmt.Errorf("error reading template file: %v", err)
    }

	htmlTemplateStr := string(htmlTemplate)


	// Prepare the data for the template
	data := struct {
		Date     string
		APIKeys  []APIKeyReport
	}{
		Date:     time.Now().Format("January 2, 2006"),
		APIKeys:  report.APIKeys,
	}

	// Parse and execute the template
    log.Println("Parsing template for report")
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"capitalize": func(str string) string {
			if len(str) > 0 {
				return string(str[0]-32) + str[1:]
			}
			return str
		},
        "toJson": toJson,
	}).Parse(htmlTemplateStr)
	if err != nil {
        log.Println("Error parsing template: ", err)
		return err
	}

	// Create the output HTML file
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Execute the template and write the output to the file
	return tmpl.Execute(file, data)
}