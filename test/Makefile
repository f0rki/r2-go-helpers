all:
	GOOS=linux GOARCH=386 go build -o hello-stripped -ldflags "-s" Hello.go
	GOOS=linux GOARCH=386 go build -o hello-normal Hello.go
	GOOS=linux GOARCH=amd64 go build -o hello-64 Hello.go
