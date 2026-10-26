package api

import (
	_ "embed"
	"net/http"
	"text/template"
)

//go:embed scripts/install.sh.tmpl
var installTmplSrc string

//go:embed scripts/uninstall.sh
var uninstallScript []byte

var installTmpl = template.Must(template.New("install").Parse(installTmplSrc))

func (a *API) installScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript")
	err := installTmpl.Execute(w, map[string]any{
		"BaseURL":    baseURL(r),
		"PublicHost": a.cfg.PublicHost,
		"EnrollPort": a.cfg.EnrollPort,
		"AgentPort":  a.cfg.AgentPort,
	})
	if err != nil {
		a.log.Error("render install.sh", "err", err)
	}
}

func (a *API) uninstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Write(uninstallScript)
}
