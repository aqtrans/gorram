module git.jba.io/go/gorram

go 1.17

replace (
	git.jba.io/go/gorram/certs => ./certs
	git.jba.io/go/gorram/checks => ./checks
	git.jba.io/go/gorram/client => ./client
	git.jba.io/go/gorram/proto => ./proto
	git.jba.io/go/gorram/server => ./server
)

require (
	github.com/fsnotify/fsnotify v1.4.9
	github.com/goccy/go-yaml v1.9.4
	github.com/gregdel/pushover v0.0.0-20200416074932-c8ad547caed4
	github.com/lib/pq v1.5.2
	github.com/shirou/gopsutil v2.20.4+incompatible
	github.com/sirupsen/logrus v1.6.0
	github.com/tevjef/go-runtime-metrics v0.0.0-20170326170900-527a54029307
	github.com/twitchtv/twirp v8.1.1+incompatible
	google.golang.org/protobuf v1.27.1
	pkg.re/essentialkaos/branca.v1 v1.3.1
)

require (
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/gdm85/go-libdeluge v0.5.6 // indirect
	github.com/gdm85/go-rencode v0.1.8 // indirect
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.3 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.7.0 // indirect
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3 // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	pkg.re/essentialkaos/check.v1 v1.0.0 // indirect
)
