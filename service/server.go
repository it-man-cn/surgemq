// Copyright (c) 2014 The SurgeMQ Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/it-man-cn/message"
	"github.com/it-man-cn/surgemq/auth"
	"github.com/it-man-cn/surgemq/sessions"
	"github.com/it-man-cn/surgemq/topics"
	"github.com/surge/glog"
)

var (
	ErrInvalidConnectionType  error = errors.New("service: Invalid connection type")
	ErrInvalidSubscriber      error = errors.New("service: Invalid subscriber")
	ErrBufferNotReady         error = errors.New("service: buffer is not ready")
	ErrBufferInsufficientData error = errors.New("service: buffer has insufficient data.")
)

const (
	DefaultKeepAlive        = 300 //5分钟
	DefaultConnectTimeout   = 2
	DefaultAckTimeout       = 20
	DefaultTimeoutRetries   = 3
	DefaultSessionsProvider = "mem"
	DefaultAuthenticator    = "mockSuccess"
	DefaultTopicsProvider   = "mem"
)

// Server is a library implementation of the MQTT server that, as best it can, complies
// with the MQTT 3.1 and 3.1.1 specs.
type Server struct {
	// The number of seconds to keep the connection live if there's no data.
	// If not set then default to 5 mins.
	KeepAlive int

	// The number of seconds to wait for the CONNECT message before disconnecting.
	// If not set then default to 2 seconds.
	ConnectTimeout int

	// The number of seconds to wait for any ACK messages before failing.
	// If not set then default to 20 seconds.
	AckTimeout int

	// The number of times to retry sending a packet if ACK is not received.
	// If no set then default to 3 retries.
	TimeoutRetries int

	// Authenticator is the authenticator used to check username and password sent
	// in the CONNECT message. If not set then default to "mockSuccess".
	Authenticator string

	// SessionsProvider is the session store that keeps all the Session objects.
	// This is the store to check if CleanSession is set to 0 in the CONNECT message.
	// If not set then default to "mem".
	SessionsProvider string

	// TopicsProvider is the topic store that keeps all the subscription topics.
	// If not set then default to "mem".
	TopicsProvider string

	// authMgr is the authentication manager that we are going to use for authenticating
	// incoming connections
	authMgr *auth.Manager

	// sessMgr is the sessions manager for keeping track of the sessions
	sessMgr *sessions.Manager

	// topicsMgr is the topics manager for keeping track of subscriptions
	topicsMgr *topics.Manager

	// The quit channel for the server. If the server detects that this channel
	// is closed, then it's a signal for it to shutdown as well.
	quit chan struct{}

	ln net.Listener

	// A list of services created by the server. We keep track of them so we can
	// gracefully shut them down if they are still alive when the server goes down.
	svcs []*service

	// Mutex for updating svcs
	mu sync.Mutex

	// A indicator on whether this server is running
	running int32

	// A indicator on whether this server has already checked configuration
	configOnce sync.Once

	subs []interface{}
	qoss []byte
}

// ListenAndServe listents to connections on the URI requested, and handles any
// incoming MQTT client sessions. It should not return until Close() is called
// or if there's some critical error that stops the server from running. The URI
// supplied should be of the form "protocol://host:port" that can be parsed by
// url.Parse(). For example, an URI could be "tcp://0.0.0.0:1883".
func (this *Server) ListenAndServe(uri string) error {
	//???
	defer atomic.CompareAndSwapInt32(&this.running, 1, 0)
	//???
	if !atomic.CompareAndSwapInt32(&this.running, 0, 1) {
		return fmt.Errorf("server/ListenAndServe: Server is already running")
	}

	this.quit = make(chan struct{})

	u, err := url.Parse(uri)
	if err != nil {
		return err
	}

	this.ln, err = net.Listen(u.Scheme, u.Host)
	if err != nil {
		return err
	}
	defer this.ln.Close()

	glog.Infof("server/ListenAndServe: server is ready...")

	var tempDelay time.Duration // how long to sleep on accept failure

	for {
		conn, err := this.ln.Accept()

		if err != nil {
			// http://zhen.org/blog/graceful-shutdown-of-go-net-dot-listeners/
			select {
			case <-this.quit:
				return nil

			default:
			}

			// Borrowed from go1.3.3/src/pkg/net/http/server.go:1699
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max { //接收失败等待时间不超过1秒
					tempDelay = max
				}
				glog.Errorf("server/ListenAndServe: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		//处理新的连接请求，请求建立成功后会进入会话保持阶段
		go this.handleConnection(conn)
	}
}

// Publish sends a single MQTT PUBLISH message to the server. On completion, the
// supplied OnCompleteFunc is called. For QOS 0 messages, onComplete is called
// immediately after the message is sent to the outgoing buffer. For QOS 1 messages,
// onComplete is called when PUBACK is received. For QOS 2 messages, onComplete is
// called after the PUBCOMP message is received.
func (this *Server) Publish(msg *message.PublishMessage, onComplete OnCompleteFunc) error {
	if err := this.checkConfiguration(); err != nil {
		return err
	}

	if msg.Retain() {
		if err := this.topicsMgr.Retain(msg); err != nil {
			glog.Errorf("Error retaining message: %v", err)
		}
	}

	if err := this.topicsMgr.Subscribers(msg.Topic(), msg.QoS(), &this.subs, &this.qoss); err != nil {
		return err
	}

	msg.SetRetain(false)

	//glog.Debugf("(server) Publishing to topic %q and %d subscribers", string(msg.Topic()), len(this.subs))
	for _, s := range this.subs {
		if s != nil {
			fn, ok := s.(*OnPublishFunc)
			if !ok {
				glog.Errorf("Invalid onPublish Function")
			} else {
				(*fn)(msg)
			}
		}
	}

	return nil
}

// Close terminates the server by shutting down all the client connections and closing
// the listener. It will, as best it can, clean up after itself.
func (this *Server) Close() error {
	// By closing the quit channel, we are telling the server to stop accepting new
	// connection.
	close(this.quit)

	// We then close the net.Listener, which will force Accept() to return if it's
	// blocked waiting for new connections.
	this.ln.Close()

	for _, svc := range this.svcs {
		glog.Infof("Stopping service %d", svc.id)
		svc.stop()
	}

	if this.sessMgr != nil {
		this.sessMgr.Close()
	}

	if this.topicsMgr != nil {
		this.topicsMgr.Close()
	}

	return nil
}

// HandleConnection is for the broker to handle an incoming connection from a client
func (this *Server) handleConnection(c io.Closer) (svc *service, err error) {
	if c == nil {
		return nil, ErrInvalidConnectionType
	}

	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	//仅执行一次，为什么这在这里，放到服务初始化时不行吗？
	err = this.checkConfiguration()
	if err != nil {
		return nil, err
	}

	conn, ok := c.(net.Conn)
	if !ok {
		return nil, ErrInvalidConnectionType
	}

	// To establish a connection, we must
	// 1. Read and decode the message.ConnectMessage from the wire
	// 2. If no decoding errors, then authenticate using username and password.
	//    Otherwise, write out to the wire message.ConnackMessage with
	//    appropriate error.
	// 3. If authentication is successful, then either create a new session or
	//    retrieve existing session
	// 4. Write out to the wire a successful message.ConnackMessage message

	// Read the CONNECT message from the wire, if error, then check to see if it's
	// a CONNACK error. If it's CONNACK error, send the proper CONNACK error back
	// to client. Exit regardless of error type.
	//每个连接都要设置超时，可以用最小堆来优化，参考goim
	//KeepAlive与ConnectTimeout的区别？？？
	conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(this.ConnectTimeout)))

	//构造Connect响应
	resp := message.NewConnackMessage()

	//解析ConnectMessage
	req, err := getConnectMessage(conn)
	if err != nil { //解析出错
		if cerr, ok := err.(message.ConnackCode); ok {
			//glog.Debugf("request   message: %s\nresponse message: %s\nerror           : %v", mreq, resp, err)
			resp.SetReturnCode(cerr)
			resp.SetSessionPresent(false)
			writeMessage(conn, resp) //写响应
		}
		return nil, err
	}
	// 权限验证
	// Authenticate the user, if error, return error and exit
	if err = this.authMgr.Authenticate(string(req.Username()), string(req.Password())); err != nil {
		resp.SetReturnCode(message.ErrBadUsernameOrPassword)
		resp.SetSessionPresent(false)
		writeMessage(conn, resp)
		return nil, err
	}

	if req.KeepAlive() == 0 {
		req.SetKeepAlive(minKeepAlive)
	}

	svc = &service{
		id:     atomic.AddUint64(&gsvcid, 1), //ID累加与clientID无关
		client: false,                        //Is this a client or server

		keepAlive:      int(req.KeepAlive()),
		connectTimeout: this.ConnectTimeout,
		ackTimeout:     this.AckTimeout,
		timeoutRetries: this.TimeoutRetries, //超时重传次数

		conn:      conn,
		sessMgr:   this.sessMgr,
		topicsMgr: this.topicsMgr,
	}
	//获取session
	err = this.getSession(svc, req, resp)
	if err != nil {
		return nil, err
	}
	//设置ConnectACK响应状态为接收请求
	resp.SetReturnCode(message.ConnectionAccepted)
	//写加Connect响应
	if err = writeMessage(c, resp); err != nil {
		return nil, err
	}
	//接收、发送流量统计
	svc.inStat.increment(int64(req.Len()))
	svc.outStat.increment(int64(resp.Len()))
	//开始进入接收发数据阶段（保持会话阶段）
	if err := svc.start(); err != nil {
		svc.stop()
		return nil, err
	}

	//this.mu.Lock()
	//this.svcs = append(this.svcs, svc)
	//this.mu.Unlock()

	glog.Infof("(%s) server/handleConnection: Connection established.", svc.cid())

	return svc, nil
}

func (this *Server) checkConfiguration() error {
	var err error

	this.configOnce.Do(func() {
		if this.KeepAlive == 0 {
			this.KeepAlive = DefaultKeepAlive
		}

		if this.ConnectTimeout == 0 {
			this.ConnectTimeout = DefaultConnectTimeout
		}

		if this.AckTimeout == 0 {
			this.AckTimeout = DefaultAckTimeout
		}

		if this.TimeoutRetries == 0 {
			this.TimeoutRetries = DefaultTimeoutRetries
		}

		if this.Authenticator == "" {
			this.Authenticator = "mockSuccess"
		}

		this.authMgr, err = auth.NewManager(this.Authenticator)
		if err != nil {
			return
		}

		if this.SessionsProvider == "" {
			this.SessionsProvider = "mem"
		}

		this.sessMgr, err = sessions.NewManager(this.SessionsProvider)
		if err != nil {
			return
		}

		if this.TopicsProvider == "" {
			this.TopicsProvider = "mem"
		}

		this.topicsMgr, err = topics.NewManager(this.TopicsProvider)

		return
	})

	return err
}

func (this *Server) getSession(svc *service, req *message.ConnectMessage, resp *message.ConnackMessage) error {
	// If CleanSession is set to 0, the server MUST resume communications with the
	// client based on state from the current session, as identified by the client
	// identifier. If there is no session associated with the client identifier the
	// server must create a new session.
	//
	// If CleanSession is set to 1, the client and server must discard any previous
	// session and start a new one. This session lasts as long as the network c
	// onnection. State data associated with this session must not be reused in any
	// subsequent session.

	var err error

	// Check to see if the client supplied an ID, if not, generate one and set
	// clean session.
	if len(req.ClientId()) == 0 {
		req.SetClientId([]byte(fmt.Sprintf("internalclient%d", svc.id)))
		req.SetCleanSession(true) //connect msg连接标志位clean session设置为1
	}

	cid := string(req.ClientId())

	// If CleanSession is NOT set, check the session store for existing session.
	// If found, return it.
	if !req.CleanSession() {
		if svc.sess, err = this.sessMgr.Get(cid); err == nil { //从sessions map中查找cid对应session是否存在
			resp.SetSessionPresent(true) //设置connack的连接确认标志位的session present标志为1，
			//更新当前service的session中的connect msg对象为当前connect msg
			if err := svc.sess.Update(req); err != nil {
				return err
			}
		}
	}

	// If CleanSession, or no existing session found, then create a new one
	if svc.sess == nil {
		if svc.sess, err = this.sessMgr.New(cid); err != nil {
			return err
		}

		resp.SetSessionPresent(false) //设置session存在标志为false，并通知client
		//初始化session对象
		if err := svc.sess.Init(req); err != nil {
			return err
		}
	}

	return nil
}
