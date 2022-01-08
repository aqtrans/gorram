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
	github.com/gregdel/pushover v0.0.0-20200416074932-c8ad547caed4
	github.com/lib/pq v1.5.2
	github.com/shirou/gopsutil v2.20.4+incompatible
	github.com/sirupsen/logrus v1.6.0
	github.com/tevjef/go-runtime-metrics v0.0.0-20170326170900-527a54029307
	github.com/twitchtv/twirp v8.1.1+incompatible
	google.golang.org/protobuf v1.27.1
	gopkg.in/yaml.v2 v2.3.0
	pkg.re/essentialkaos/branca.v1 v1.3.1
)

require (
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.3 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.7.0 // indirect
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3 // indirect
	golang.org/x/sys v0.0.0-20210616094352-59db8d763f22 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	pkg.re/essentialkaos/check.v1 v1.0.0 // indirect
)
