module gorram/server

go 1.13

require (
	git.jba.io/go/gorram/certs v0.0.0-00010101000000-000000000000
	git.jba.io/go/gorram/proto v0.0.0-00010101000000-000000000000
	github.com/fsnotify/fsnotify v1.4.7
	github.com/gregdel/pushover v0.0.0-20180208231006-1e03358b8e7e
	github.com/konsorten/go-windows-terminal-sequences v1.0.2
	github.com/pelletier/go-toml v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/tevjef/go-runtime-metrics v0.0.0-20170326170900-527a54029307
	golang.org/x/sys v0.0.0-20190422165155-953cdadca894
	google.golang.org/grpc v1.24.0
	gopkg.in/yaml.v2 v2.2.2
)

replace (
	git.jba.io/go/gorram/certs => ../certs
	git.jba.io/go/gorram/proto => ../proto
)
