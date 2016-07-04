//DNS resolver with SOCKS5 proxy
package main

import (
	"crypto/md5"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Unknwon/goconfig"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

var (
	_localDNS    = flag.String("localdns", "127.0.0.1:53", "Address:port for local DNS requests")
	_socks5Proxy = flag.String("socks5", "", "SOCKS5 address:port")
	_remoteDNS   = flag.String("remotedns", "8.8.8.8:53,8.8.4.4:53", "Address:port of upstream DNS servers (comma seperated for multiple values)")

	encache    = flag.Bool("cache", true, "Enable dns cache")
	debugShow  = flag.Bool("v", false, "Debug msg")
	configfile = flag.String("configfile", "conf.ini", "Load config from file (default:conf.ini)")

	dnsCache map[string]*dns.Msg
)

func fileExist(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil || os.IsExist(err)
}

func toMd5(data string) string {
	m := md5.New()
	m.Write([]byte(data))
	return hex.EncodeToString(m.Sum(nil))
}

func isTransfer(req *dns.Msg) bool {
	for _, q := range req.Question {
		switch q.Qtype {
		case dns.TypeIXFR, dns.TypeAXFR:
			return true
		}
	}
	return false
}

func SaveDnsCache(modfile string) {
	file, err := os.Create(modfile)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer file.Close()

	enc := gob.NewEncoder(file)
	err2 := enc.Encode(dnsCache)
	if err2 != nil {
		fmt.Println(err2)
	}
}

func LoadDnsCache(modfile string) {
	file, err := os.Open(modfile)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer file.Close()

	dec := gob.NewDecoder(file)
	err2 := dec.Decode(&dnsCache)

	if err2 != nil {
		fmt.Println(err2)
		return
	}
}

type proxyResponse struct {
	*dns.Msg
	err error
}

type proxyRequest struct {
	*dns.Msg
	response chan proxyResponse
}

func handleRequest(req *dns.Msg, dlr *dialer, done chan<- proxyResponse) {
	conn, err := dlr.Dial()
	if err != nil {
		done <- proxyResponse{nil, err}
		return
	}

	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Println("conn.Close() error: ", err.Error())
		}
	}()

	if isTransfer(req) {
		err := errors.New("need to handle transfers!")
		done <- proxyResponse{nil, err}
		return
	}

	dnsConn := &dns.Conn{Conn: conn}
	if err := dnsConn.WriteMsg(req); err != nil {
		done <- proxyResponse{nil, err}
		return
	}

	resp, err := dnsConn.ReadMsg()
	if err != nil {
		done <- proxyResponse{nil, err}
		return

	} else if resp.Id != req.Id {
		done <- proxyResponse{nil, errors.New(fmt.Sprintf("ERROR: resp.Id %v != req.Id %v", resp.Id, req.Id))}
		return
	}
	done <- proxyResponse{resp, nil}
}

func proxyWorker(c chan proxyRequest, dialer1, dialer2 *dialer) {
	for req := range c {
		done := make(chan proxyResponse, 3)

		reqMsgCopy := req.Msg.Copy()
		go handleRequest(reqMsgCopy, dialer1, done)
		go handleRequest(req.Msg, dialer2, done)

		select {
		case <-time.After(10 * time.Second):
			err := errors.New("general timeout")
			req.response <- proxyResponse{nil, err}

		case r := <-done:
			if r.err != nil {
				select {
				case <-time.After(250 * time.Millisecond):
					break
				case r2 := <-done:
					r = r2
				}
			}

			req.response <- r
		}
	}
}

func route(w dns.ResponseWriter, req *dns.Msg, jobQueue chan proxyRequest) {
	if len(req.Question) == 0 {
		fmt.Println("ERROR: len(req.Question)==0")
		dns.HandleFailed(w, req)
		return
	}
	if *debugShow {
		log.Printf("[%s] QUERY >>>>>>>>>\n%s\n", w.RemoteAddr(), req)
	} else {
		names := ""
		for _, vv := range req.Question {
			names = names + " " + vv.Name
		}
		log.Printf("[%s] QUERY %s\n", w.RemoteAddr(), names)
	}
	key := fmt.Sprintf("%s", req)
	key = toMd5(key)

	if *encache {
		if v, ok := dnsCache[key]; ok {
			if *debugShow {
				log.Printf("[%s] RETURN by dnsCache >>>>>>>>>\n%s\n", w.RemoteAddr(), v)
			} else {
				fmt.Printf("                    [%s] RETURN by dnsCache\n", w.RemoteAddr())
				tmp := "                    >"
				for kk, vv := range v.Answer {
					fmt.Println(tmp, kk, vv)
				}
			}
			if err := w.WriteMsg(v); err != nil {
				fmt.Printf("ERROR WriteMsg(): on request %s", req)
				dns.HandleFailed(w, req)
				return
			}
			return
		}
	}

	responseChan := make(chan proxyResponse, 0)
	jobQueue <- proxyRequest{req, responseChan}
	x := <-responseChan
	close(responseChan)

	if x.err != nil {
		fmt.Printf("ERROR: %s on request %s\n", x.err, req)
		dns.HandleFailed(w, req)
		return
	}

	if err := w.WriteMsg(x.Msg); err != nil {
		fmt.Printf("ERROR WriteMsg(): %s on request %s", x.err, req)
		dns.HandleFailed(w, req)
		return
	}

	dnsCache[key] = x.Msg
	if *debugShow {
		log.Printf("[%s] RETURN >>>>>>>>>\n%s\n", w.RemoteAddr(), x.Msg)
	} else {
		fmt.Printf("                    [%s] RETURN\n", w.RemoteAddr())
		tmp := "                    >"
		for kk, vv := range x.Msg.Answer {
			fmt.Println(tmp, kk, vv)
		}
	}
}

type dialer struct {
	dnsServer   string
	socks5Proxy string
}

func (d *dialer) Dial() (net.Conn, error) {
	if d.socks5Proxy == "" {
		return proxy.Direct.Dial("tcp", d.dnsServer)
	}
	dialer, err := proxy.SOCKS5("tcp", d.socks5Proxy, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return dialer.Dial("tcp", d.dnsServer)
}

type server struct {
	jobQueue  chan<- proxyRequest
	udpServer *dns.Server
	tcpServer *dns.Server
}

func (s *server) ListenAndServe() error {
	resChan := make(chan error, 4)
	go func() {
		resChan <- s.udpServer.ListenAndServe()
	}()
	go func() {
		resChan <- s.tcpServer.ListenAndServe()
	}()

	go func() {
		time.Sleep(2 * time.Second)

		m := new(dns.Msg)
		m.SetQuestion("google.com.", dns.TypeSOA)

		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.udpServer.Addr)
		if err == nil {
			if r != nil && r.Rcode != dns.RcodeSuccess {
				err = fmt.Errorf("invalid answer: %s", r)
			}
		}
		if err == nil {
			if *debugShow {
				fmt.Printf("Quick test >>>>>>\npassed of %s\n", m.String())
			} else {
				fmt.Println("remoteDNS Connection successful")
			}
		}
		resChan <- err
	}()

	for i := 0; i < cap(resChan); i++ {
		if err := <-resChan; err != nil {
			return err
		}
	}
	return nil
}

func newServer(localDNS string, remoteDNS []string, socks5Proxy string, numWorkers int) (*server, error) {
	if socks5Proxy == "" {
		return nil, errors.New("No SOCKS5 proxy specified")
	}
	fmt.Printf("Using SOCKS5 proxy %v\n", socks5Proxy)

	if len(remoteDNS) == 0 || len(remoteDNS[0]) == 0 {
		return nil, errors.New("No remote DNS specified")
	}
	fmt.Printf("Remote DNS %v\n", remoteDNS[0])

	dns_dialer1 := &dialer{remoteDNS[0], socks5Proxy}
	var dns_dialer2 *dialer = nil
	if len(remoteDNS) > 1 && len(remoteDNS[1]) > 0 {
		dns_dialer2 = &dialer{remoteDNS[1], socks5Proxy}
		fmt.Printf("Remote DNS %v\n", remoteDNS[1])
	}
	if len(remoteDNS) > 2 {
		fmt.Printf("Ignoring anything beyond first two remote DNS servers: %v\n", remoteDNS[2:])
	}

	fmt.Printf("Local DNS address %v\n", localDNS)

	jobQueue := make(chan proxyRequest, numWorkers)
	for i := 0; i < numWorkers; i++ {
		go proxyWorker(jobQueue, dns_dialer1, dns_dialer2)
	}

	serveMux := dns.NewServeMux()
	serveMux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		route(w, req, jobQueue)
	})

	udpServer := &dns.Server{
		Addr:    localDNS,
		Net:     "udp",
		Handler: serveMux,
	}
	tcpServer := &dns.Server{
		Addr:    localDNS,
		Net:     "tcp",
		Handler: serveMux,
	}

	s := &server{
		jobQueue:  jobQueue,
		udpServer: udpServer,
		tcpServer: tcpServer,
	}
	return s, nil
}

func loadFromFile() {
	c, err := goconfig.LoadConfigFile(*configfile)
	if err != nil {
		fmt.Println("Load Config failed:", err)
		os.Exit(1)
	}

	test1, err := c.GetValue("Config", "Socks5")
	if err != nil {
		fmt.Println("Load Config failed([Config]Socks5):", err)
		os.Exit(1)
	}

	test2, err := c.GetValue("Config", "RemoteDNS")
	if err != nil {
		fmt.Println("Load Config failed([Config]RemoteDNS):", err)
		os.Exit(1)
	}

	test3, err := c.GetValue("Config", "LocalDNS")
	if err != nil {
		fmt.Println("Load Config failed([Config]LocalDNS):", err)
		os.Exit(1)
	}

	test4, err := c.Bool("Config", "Cache")
	if err != nil {
		fmt.Println("Load Config failed([Config]Cache):", err)
		os.Exit(1)
	}

	test5, err := c.Bool("Config", "Debug")
	if err != nil {
		fmt.Println("Load Config failed([Config]Debug):", err)
		os.Exit(1)
	}

	*_localDNS = test3
	*_socks5Proxy = test1
	*_remoteDNS = test2
	*encache = test4
	*debugShow = test5

	fmt.Println("Load Config form file:", *configfile)
}

func main() {
	flag.Parse()
	if (len(os.Args) == 1) || (*_socks5Proxy == "") {
		if fileExist(*configfile) {
			loadFromFile()
		} else {
			flag.Usage()
			os.Exit(1)
		}
	}

	numWorkers := runtime.NumCPU() * 4
	remoteDNS := strings.Split(*_remoteDNS, ",")

	dnsCache = make(map[string]*dns.Msg)
	//LoadDnsCache("dnsCache.dat")
	s, err := newServer(*_localDNS, remoteDNS, *_socks5Proxy, numWorkers)
	if err != nil {
		fmt.Println(err)
		return
	}

	if err := s.ListenAndServe(); err != nil {
		fmt.Println(err)
		return
	}
}
