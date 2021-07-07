module git.jba.io/go/gorram

go 1.16

replace (
	git.jba.io/go/gorram/certs => ./certs
	git.jba.io/go/gorram/checks => ./checks
	git.jba.io/go/gorram/client => ./client
	git.jba.io/go/gorram/proto => ./proto
	git.jba.io/go/gorram/server => ./server
)

require (
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/fsnotify/fsnotify v1.4.9
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/gregdel/pushover v0.0.0-20200416074932-c8ad547caed4
	github.com/lib/pq v1.5.2
	github.com/shirou/gopsutil v2.20.4+incompatible
	github.com/sirupsen/logrus v1.6.0
	github.com/tevjef/go-runtime-metrics v0.0.0-20170326170900-527a54029307
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e // indirect
	golang.org/x/sys v0.0.0-20210616094352-59db8d763f22 // indirect
	google.golang.org/genproto v0.0.0-20210624195500-8bfb893ecb84 // indirect
	google.golang.org/grpc v1.38.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/yaml.v2 v2.3.0
)
