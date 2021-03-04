package nginx

import (
	"bytes"
	"html/template"

	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var nginxConfigTemplate = `
worker_processes 1;

events { worker_connections 1024; }

http {
    sendfile on;
		server_tokens off;

    server {
      listen 8080;
{{ range .Spec.Rules -}}
{{ range .IngressRuleValue.HTTP.Paths }}
        location {{ .Path }} {
          proxy_pass         http://{{ .Backend.ServiceName }}:{{ IntValue .Backend.ServicePort }};
          proxy_redirect     off;
          proxy_set_header   Host $host;
          proxy_set_header   X-Real-IP $remote_addr;
          proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header   X-Forwarded-Host $server_name;
       }
{{ end }}
{{- end }}
    }
}
`

func BuildNginxConfig(ingress *extensionsv1beta1.Ingress) string {
	t, err := template.New("").Funcs(template.FuncMap{
		"IntValue": func(d intstr.IntOrString) int {
			return d.IntValue()
		},
	}).Parse(nginxConfigTemplate)
	if err != nil {
		panic(err)
	}

	buf := bytes.NewBuffer([]byte{})
	if err := t.Execute(buf, *ingress); err != nil {
		panic(err)
	}

	return buf.String()
}
