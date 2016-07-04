::@del /f /q /a cache.dat
@go build -ldflags "-s -w" proxyDns.go
::@go build -ldflags "-H windowsgui" proxyDns.go
@pause