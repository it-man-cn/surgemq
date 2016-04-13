package service

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

type ServerCounter struct {
	Count int64
}

func InitHTTP(httpAddr string) (err error) {
	// http listen
	httpServeMux := http.NewServeMux()
	httpServeMux.HandleFunc("/count", Count)
	go httpListen(httpServeMux, httpAddr)

	return
}

func httpListen(mux *http.ServeMux, addr string) {
	httpServer := &http.Server{Handler: mux, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	httpServer.SetKeepAlivesEnabled(true)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("net.Listen( \"%s\") error(%v)\n", addr, err)
		panic(err)
	}
	if err := httpServer.Serve(l); err != nil {
		fmt.Printf("server.Serve() error(%v)\n", err)
		panic(err)
	}
}

func Count(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	var (
		res = map[string]interface{}{"ret": 1}
	)
	defer retWrite(w, r, res, time.Now())

	res["data"] = &ServerCounter{Count: OnlineCount()}

	return
}

// retWrite marshal the result and write to client(get).
func retWrite(w http.ResponseWriter, r *http.Request, res map[string]interface{}, start time.Time) {
	data, err := json.Marshal(res)
	if err != nil {
		fmt.Printf("json.Marshal(\"%v\") error(%v)\n", res, err)
		return
	}
	dataStr := string(data)
	if _, err := w.Write([]byte(dataStr)); err != nil {
		fmt.Printf("w.Write(\"%s\") error(%v)\n", dataStr, err)
	}
	//fmt.Printf("req: \"%s\", get: res:\"%s\", ip:\"%s\", time:\"%fs\"\n", r.URL.String(), dataStr, r.RemoteAddr, time.Now().Sub(start).Seconds())
}
