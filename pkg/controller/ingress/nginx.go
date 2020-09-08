package ingress

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
		client_max_body_size 100M;

    server {
      listen {{ .Port }};
{{ range .Ingress.Spec.Rules -}}
{{ range .IngressRuleValue.HTTP.Paths }}
        location {{ .Path }} {
          proxy_pass         http://{{ .Backend.ServiceName }}:{{ IntValue .Backend.ServicePort }};
          proxy_redirect     off;
          proxy_set_header   Host $host;
          proxy_set_header   X-Real-IP $remote_addr;
          proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header   X-Forwarded-Host $server_name;
				  proxy_http_version 1.1;
				  proxy_set_header Connection "";
				  proxy_ignore_client_abort on;
       }
{{ end }}
{{- end }}
    }
}
`

func buildNginxConfig(instance *extensionsv1beta1.Ingress) string {
	t, err := template.New("").Funcs(template.FuncMap{
		"IntValue": func(d intstr.IntOrString) int {
			return d.IntValue()
		},
	}).Parse(nginxConfigTemplate)
	if err != nil {
		panic(err)
	}

	buf := bytes.NewBuffer([]byte{})
	if err := t.Execute(buf, struct {
		Ingress *extensionsv1beta1.Ingress
		Port    int
	}{
		Ingress: instance,
		Port:    getNginxServicePort(instance),
	}); err != nil {
		panic(err)
	}

	return buf.String()
}
