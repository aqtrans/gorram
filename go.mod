module git.jba.io/go/gorram

go 1.13

replace (
	git.jba.io/go/gorram/certs => ./certs
	git.jba.io/go/gorram/checks => ./checks
	git.jba.io/go/gorram/client => ./client
	git.jba.io/go/gorram/proto => ./proto
	git.jba.io/go/gorram/server => ./server
)

require (
	git.jba.io/go/gorram/checks v0.0.0-00010101000000-000000000000 // indirect
	git.jba.io/go/gorram/server v0.0.0-00010101000000-000000000000 // indirect
	github.com/gregdel/pushover v0.0.0-20190217183207-15d3fef40636 // indirect
	github.com/pelletier/go-toml v1.6.0 // indirect
	gopkg.in/yaml.v2 v2.2.7 // indirect
)
