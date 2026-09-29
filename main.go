package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"
	"golang.org/x/time/rate"
)

type Upstream struct {
	Address  string `json:"address"`
	Type     string `json:"type"`
	AuthUser string `json:"auth_user"`
	AuthPass string `json:"auth_pass"`
	Location string `json:"location"`
	Weight   int    `json:"weight"`
}

type DeviceProfile struct {
	Name         string            `json:"name"`
	UserAgent    string            `json:"user_agent"`
	AcceptLang   string            `json:"accept_language"`
	Accept       string            `json:"accept"`
	TLSVersion   uint16            `json:"tls_version"`
	CipherSuites []uint16          `json:"cipher_suites"`
	Headers      map[string]string `json:"headers"`
	Upstreams    []Upstream        `json:"upstreams"`
}

type Config struct {
	Port           int             `json:"port"`
	UDPPort        int             `json:"udp_port"`
	UDPEnabled     bool            `json:"udp_enabled"`
	HTTPPort       int             `json:"http_port"`
	HTTPEnabled    bool            `json:"http_enabled"`
	MaxConnections int             `json:"max_connections"`
	IdleTimeoutSec int             `json:"idle_timeout_sec"`
	Verbose        bool            `json:"verbose"`
	LatencyMs      int             `json:"latency_ms"`
	JitterMs       int             `json:"jitter_ms"`
	PacketLoss     float64         `json:"packet_loss"`
	BandwidthBps   int64           `json:"bandwidth_bps"`
	AuthEnabled    bool            `json:"auth_enabled"`
	AuthUser       string          `json:"auth_user"`
	AuthPass       string          `json:"auth_pass"`
	AllowedCIDRs   []string        `json:"allowed_cidrs"`
	BlockedCIDRs   []string        `json:"blocked_cidrs"`
	GeoIPDBPath    string          `json:"geoip_db_path"`
	Profiles       []DeviceProfile `json:"profiles"`
	DefaultProfile string          `json:"default_profile"`
	Upstreams      []Upstream      `json:"upstreams"`
}

func DefaultConfig() *Config {
	return &Config{
		Port:           1080,
		UDPPort:        1081,
		UDPEnabled:     true,
		HTTPPort:       8080,
		HTTPEnabled:    false,
		MaxConnections: 100,
		IdleTimeoutSec: 300,
		LatencyMs:      0,
		JitterMs:       0,
		PacketLoss:     0,
		BandwidthBps:   0,
		Verbose:        false,
	}
}

func parseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		nets = append(nets, n)
	}
	return nets, nil
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

var bufferPool = sync.Pool{
	New: func() interface{} { return make([]byte, 32*1024) },
}

type LatencyConn struct {
	net.Conn
	latency    time.Duration
	jitter     time.Duration
	packetLoss float64
	limiter    *rate.Limiter
	readBytes  int64
	writeBytes int64
	mu         sync.Mutex
}

func NewLatencyConn(conn net.Conn, latency, jitter time.Duration, loss float64, bps int64) *LatencyConn {
	var limiter *rate.Limiter
	if bps > 0 {
		limiter = rate.NewLimiter(rate.Limit(bps), int(bps))
	}
	return &LatencyConn{
		Conn:       conn,
		latency:    latency,
		jitter:     jitter,
		packetLoss: loss,
		limiter:    limiter,
	}
}

func (c *LatencyConn) Read(b []byte) (int, error) {
	if c.packetLoss > 0 && rand.Float64() < c.packetLoss {
		return 0, nil
	}
	if c.limiter != nil {
		if err := c.limiter.WaitN(context.Background(), len(b)); err != nil {
			return 0, err
		}
	}
	c.sleepLatency()
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(&c.readBytes, int64(n))
	}
	return n, err
}

func (c *LatencyConn) Write(b []byte) (int, error) {
	if c.packetLoss > 0 && rand.Float64() < c.packetLoss {
		return len(b), nil
	}
	if c.limiter != nil {
		if err := c.limiter.WaitN(context.Background(), len(b)); err != nil {
			return 0, err
		}
	}
	c.sleepLatency()
	n, err := c.Conn.Write(b)
	if n > 0 {
		atomic.AddInt64(&c.writeBytes, int64(n))
	}
	return n, err
}

func (c *LatencyConn) sleepLatency() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.latency == 0 && c.jitter == 0 {
		return
	}
	jitter := time.Duration(0)
	if c.jitter > 0 {
		jitter = time.Duration(rand.Int63n(int64(c.jitter)*2)) - c.jitter
	}
	sleep := c.latency + jitter
	if sleep > 0 {
		time.Sleep(sleep)
	}
}

func (c *LatencyConn) Stats() (read, write int64) {
	return atomic.LoadInt64(&c.readBytes), atomic.LoadInt64(&c.writeBytes)
}

type ConnStats struct {
	ID         uint64
	RemoteAddr string
	TargetAddr string
	Start      time.Time
	ReadBytes  int64
	WriteBytes int64
	Protocol   string
	Profile    string
	Upstream   string
}

type Tracker struct {
	sync.RWMutex
	conns      map[uint64]*ConnStats
	nextID     uint64
	totalConns uint64
	active     int32
}

func NewTracker() *Tracker {
	return &Tracker{conns: make(map[uint64]*ConnStats)}
}

func (t *Tracker) Add(remote, target, proto, profile, upstream string) *ConnStats {
	id := atomic.AddUint64(&t.nextID, 1)
	cs := &ConnStats{
		ID:         id,
		RemoteAddr: remote,
		TargetAddr: target,
		Start:      time.Now(),
		Protocol:   proto,
		Profile:    profile,
		Upstream:   upstream,
	}
	t.Lock()
	t.conns[id] = cs
	t.Unlock()
	atomic.AddInt32(&t.active, 1)
	atomic.AddUint64(&t.totalConns, 1)
	return cs
}

func (t *Tracker) Remove(id uint64) {
	t.Lock()
	delete(t.conns, id)
	t.Unlock()
	atomic.AddInt32(&t.active, -1)
}

func (t *Tracker) Update(id uint64, read, write int64) {
	t.RLock()
	cs, ok := t.conns[id]
	t.RUnlock()
	if ok {
		cs.ReadBytes = read
		cs.WriteBytes = write
	}
}

func (t *Tracker) Active() int32 { return atomic.LoadInt32(&t.active) }
func (t *Tracker) Total() uint64 { return atomic.LoadUint64(&t.totalConns) }
func (t *Tracker) All() []*ConnStats {
	t.RLock()
	defer t.RUnlock()
	res := make([]*ConnStats, 0, len(t.conns))
	for _, cs := range t.conns {
		res = append(res, cs)
	}
	return res
}

type udpNatEntry struct {
	clientAddr *net.UDPAddr
	targetAddr *net.UDPAddr
	expires    time.Time
}

type UDPNAT struct {
	sync.RWMutex
	entries map[string]*udpNatEntry
}

func NewUDPNAT() *UDPNAT {
	return &UDPNAT{entries: make(map[string]*udpNatEntry)}
}

func (n *UDPNAT) Get(target *net.UDPAddr) (*net.UDPAddr, bool) {
	n.RLock()
	defer n.RUnlock()
	key := target.String()
	entry, ok := n.entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.clientAddr, true
}

func (n *UDPNAT) Set(client, target *net.UDPAddr, ttl time.Duration) {
	n.Lock()
	defer n.Unlock()
	key := target.String()
	n.entries[key] = &udpNatEntry{
		clientAddr: client,
		targetAddr: target,
		expires:    time.Now().Add(ttl),
	}
}

func (n *UDPNAT) Cleanup() {
	n.Lock()
	defer n.Unlock()
	now := time.Now()
	for k, v := range n.entries {
		if now.After(v.expires) {
			delete(n.entries, k)
		}
	}
}

type ProfileManager struct {
	sync.RWMutex
	profiles    map[string]*DeviceProfile
	defaultName string
	geoip       *geoip2.Reader
	geoipPath   string
	upstreams   []Upstream
}

func NewProfileManager(cfg *Config) (*ProfileManager, error) {
	pm := &ProfileManager{
		profiles:    make(map[string]*DeviceProfile),
		defaultName: cfg.DefaultProfile,
		upstreams:   cfg.Upstreams,
	}
	if cfg.GeoIPDBPath != "" {
		db, err := geoip2.Open(cfg.GeoIPDBPath)
		if err != nil {
			return nil, fmt.Errorf("geoip: %w", err)
		}
		pm.geoip = db
		pm.geoipPath = cfg.GeoIPDBPath
	}
	for i := range cfg.Profiles {
		pm.profiles[cfg.Profiles[i].Name] = &cfg.Profiles[i]
	}
	return pm, nil
}

func (pm *ProfileManager) Close() {
	if pm.geoip != nil {
		pm.geoip.Close()
	}
}

func (pm *ProfileManager) GetProfile(name string) *DeviceProfile {
	pm.RLock()
	defer pm.RUnlock()
	if name == "" {
		name = pm.defaultName
	}
	if p, ok := pm.profiles[name]; ok {
		return p
	}
	return nil
}

func (pm *ProfileManager) SelectUpstream(profile *DeviceProfile, targetAddr string) (*Upstream, error) {
	upstreams := profile.Upstreams
	if len(upstreams) == 0 {
		upstreams = pm.upstreams
	}
	if len(upstreams) == 0 {
		return nil, nil
	}
	if pm.geoip != nil {
		host, _, err := net.SplitHostPort(targetAddr)
		if err != nil {
			host = targetAddr
		}
		ip := net.ParseIP(host)
		if ip != nil {
			record, err := pm.geoip.Country(ip)
			if err == nil && record != nil {
				country := record.Country.IsoCode
				for _, u := range upstreams {
					if strings.EqualFold(u.Location, country) {
						return &u, nil
					}
				}
			}
		}
	}
	return &upstreams[0], nil
}

type HTTPProxy struct {
	server     *Server
	conn       net.Conn
	profile    *DeviceProfile
	upstream   *Upstream
	statsID    uint64
	remoteAddr string
	targetAddr string
}

func (h *HTTPProxy) Handle() {
	defer h.conn.Close()
	reader := bufio.NewReader(h.conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		h.conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	if req.Body != nil {
		defer req.Body.Close()
	}

	if req.Method == "CONNECT" {
		h.handleConnect(req)
	} else {
		h.handleHTTP(req)
	}
}

func (h *HTTPProxy) handleConnect(req *http.Request) {
	target := req.URL.Host
	if target == "" {
		h.conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	var conn net.Conn
	var err error
	if h.upstream != nil {
		conn, err = dialUpstream(h.upstream, target)
	} else {
		conn, err = net.DialTimeout("tcp", target, 10*time.Second)
	}
	if err != nil {
		h.conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer conn.Close()
	h.conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	h.tunnel(h.conn, conn)
}

func (h *HTTPProxy) handleHTTP(req *http.Request) {
	if h.profile != nil {
		if h.profile.UserAgent != "" {
			req.Header.Set("User-Agent", h.profile.UserAgent)
		}
		if h.profile.AcceptLang != "" {
			req.Header.Set("Accept-Language", h.profile.AcceptLang)
		}
		if h.profile.Accept != "" {
			req.Header.Set("Accept", h.profile.Accept)
		}
		for k, v := range h.profile.Headers {
			req.Header.Set(k, v)
		}
	}
	targetHost := req.URL.Host
	if targetHost == "" {
		targetHost = req.Host
	}
	if targetHost == "" {
		h.conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	var conn net.Conn
	var err error
	if h.upstream != nil {
		conn, err = dialUpstream(h.upstream, targetHost)
	} else {
		conn, err = net.DialTimeout("tcp", targetHost, 10*time.Second)
	}
	if err != nil {
		h.conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer conn.Close()
	if req.URL.Host == "" {
		req.URL.Scheme = "http"
		req.URL.Host = targetHost
	}
	req.Host = targetHost
	if err := req.Write(conn); err != nil {
		return
	}
	io.Copy(h.conn, conn)
}

func (h *HTTPProxy) tunnel(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(target, client)
	}()
	go func() {
		defer wg.Done()
		io.Copy(client, target)
	}()
	wg.Wait()
}

func dialUpstream(up *Upstream, targetAddr string) (net.Conn, error) {
	if up == nil {
		return net.Dial("tcp", targetAddr)
	}
	switch up.Type {
	case "socks5":
		var auth *socks5Auth
		if up.AuthUser != "" {
			auth = &socks5Auth{User: up.AuthUser, Pass: up.AuthPass}
		}
		return socks5Dial(up.Address, targetAddr, auth)
	case "http":
		return httpProxyDial(up.Address, targetAddr, up.AuthUser, up.AuthPass)
	default:
		return net.Dial("tcp", targetAddr)
	}
}

type socks5Auth struct {
	User, Pass string
}

func socks5Dial(proxyAddr, targetAddr string, auth *socks5Auth) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	if auth != nil {
		conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	} else {
		conn.Write([]byte{0x05, 0x01, 0x00})
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, err
	}
	if buf[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("bad socks version")
	}
	if buf[1] == 0x02 && auth != nil {
		conn.Write([]byte{0x01, byte(len(auth.User))})
		conn.Write([]byte(auth.User))
		conn.Write([]byte{byte(len(auth.Pass))})
		conn.Write([]byte(auth.Pass))
		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			conn.Close()
			return nil, err
		}
		if buf[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("auth failed")
		}
	} else if buf[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks handshake failed")
	}
	host, portStr, _ := net.SplitHostPort(targetAddr)
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	buf2 := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf2); err != nil {
		conn.Close()
		return nil, err
	}
	if buf2[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks connect failed: %d", buf2[1])
	}
	var addrLen int
	switch buf2[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			conn.Close()
			return nil, err
		}
		addrLen = int(lenByte[0]) + 1
	}
	discard := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, discard); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func httpProxyDial(proxyAddr, targetAddr, user, pass string) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
	if user != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("proxy returned %d", resp.StatusCode)
	}
	return conn, nil
}

type Server struct {
	mu           sync.RWMutex
	cfg          *Config
	listener     net.Listener
	udpConn      *net.UDPConn
	httpListener net.Listener
	running      bool
	done         chan struct{}
	tracker      *Tracker
	udpNAT       *UDPNAT
	httpSrv      *http.Server
	allowNets    []*net.IPNet
	blockNets    []*net.IPNet
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	pm           *ProfileManager
}

func NewServer(cfg *Config) (*Server, error) {
	allowNets, err := parseCIDRs(cfg.AllowedCIDRs)
	if err != nil {
		return nil, fmt.Errorf("allowed CIDRs: %w", err)
	}
	blockNets, err := parseCIDRs(cfg.BlockedCIDRs)
	if err != nil {
		return nil, fmt.Errorf("blocked CIDRs: %w", err)
	}
	if len(allowNets) == 0 {
		_, all, _ := net.ParseCIDR("0.0.0.0/0")
		allowNets = []*net.IPNet{all}
	}
	ctx, cancel := context.WithCancel(context.Background())
	pm, err := NewProfileManager(cfg)
	if err != nil {
		cancel()
		return nil, err
	}
	return &Server{
		cfg:       cfg,
		done:      make(chan struct{}),
		tracker:   NewTracker(),
		udpNAT:    NewUDPNAT(),
		allowNets: allowNets,
		blockNets: blockNets,
		ctx:       ctx,
		cancel:    cancel,
		pm:        pm,
	}, nil
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return fmt.Errorf("already running")
	}
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.Port))
	if err != nil {
		return fmt.Errorf("TCP listen: %w", err)
	}
	s.listener = l
	if s.cfg.UDPEnabled {
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", s.cfg.UDPPort))
		if err != nil {
			l.Close()
			return fmt.Errorf("UDP resolve: %w", err)
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			l.Close()
			return fmt.Errorf("UDP listen: %w", err)
		}
		s.udpConn = udpConn
		s.wg.Add(1)
		go s.udpLoop()
	}
	if s.cfg.HTTPEnabled {
		httpListener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.HTTPPort))
		if err != nil {
			l.Close()
			if s.udpConn != nil {
				s.udpConn.Close()
			}
			return fmt.Errorf("HTTP listen: %w", err)
		}
		s.httpListener = httpListener
		s.wg.Add(1)
		go s.httpAcceptLoop()
	}
	s.running = true
	log.Printf("SOCKS5 proxy on port %d, HTTP proxy on port %d", s.cfg.Port, s.cfg.HTTPPort)
	s.wg.Add(1)
	go s.acceptLoop()
	s.startHTTPAPI()
	return nil
}

func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return fmt.Errorf("not running")
	}
	s.running = false
	s.mu.Unlock()
	s.cancel()
	if s.listener != nil {
		s.listener.Close()
	}
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	if s.httpListener != nil {
		s.httpListener.Close()
	}
	if s.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpSrv.Shutdown(ctx)
	}
	if s.pm != nil {
		s.pm.Close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		log.Println("All goroutines stopped")
	case <-time.After(10 * time.Second):
		log.Println("Timeout waiting for goroutines")
	}
	log.Println("Proxy stopped")
	return nil
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}
		if s.tracker.Active() >= int32(s.cfg.MaxConnections) {
			log.Printf("Max connections reached, rejecting %s", conn.RemoteAddr())
			conn.Close()
			continue
		}
		if !s.isAllowed(conn.RemoteAddr()) {
			log.Printf("Blocked connection from %s", conn.RemoteAddr())
			conn.Close()
			continue
		}
		s.wg.Add(1)
		go s.handleTCP(conn)
	}
}

func (s *Server) httpAcceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.httpListener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Printf("HTTP Accept error: %v", err)
				continue
			}
		}
		if s.tracker.Active() >= int32(s.cfg.MaxConnections) {
			conn.Close()
			continue
		}
		if !s.isAllowed(conn.RemoteAddr()) {
			conn.Close()
			continue
		}
		s.wg.Add(1)
		go s.handleHTTP(conn)
	}
}

func (s *Server) isAllowed(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if len(s.blockNets) > 0 && ipInNets(ip, s.blockNets) {
		return false
	}
	return ipInNets(ip, s.allowNets)
}

func (s *Server) handleTCP(client net.Conn) {
	defer s.wg.Done()
	defer client.Close()
	remoteAddr := client.RemoteAddr().String()
	if err := s.doHandshake(client); err != nil {
		if s.cfg.Verbose {
			log.Printf("Handshake from %s: %v", remoteAddr, err)
		}
		return
	}
	target, cmd, err := s.readRequest(client)
	if err != nil {
		if s.cfg.Verbose {
			log.Printf("Request from %s: %v", remoteAddr, err)
		}
		return
	}
	profileName := s.cfg.DefaultProfile
	profile := s.pm.GetProfile(profileName)
	if profile == nil {
		profile = s.pm.GetProfile("")
	}
	upstream, _ := s.pm.SelectUpstream(profile, target)
	var stats *ConnStats
	if upstream != nil {
		stats = s.tracker.Add(remoteAddr, target, "socks5", profile.Name, upstream.Address)
	} else {
		stats = s.tracker.Add(remoteAddr, target, "socks5", profile.Name, "direct")
	}
	defer s.tracker.Remove(stats.ID)
	switch cmd {
	case 0x01:
		s.proxyConnect(client, remoteAddr, target, profile, upstream, stats)
	case 0x02:
		s.proxyBind(client, remoteAddr, target, profile, upstream, stats)
	case 0x03:
		s.proxyUDPAssociate(client, remoteAddr, target, profile, upstream, stats)
	default:
		s.sendReply(client, 0x07)
	}
}

func (s *Server) handleHTTP(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	profile := s.pm.GetProfile(s.cfg.DefaultProfile)
	upstream, _ := s.pm.SelectUpstream(profile, "")
	stats := s.tracker.Add(remoteAddr, "http", "http", profile.Name, "direct")
	defer s.tracker.Remove(stats.ID)
	hp := &HTTPProxy{
		server:     s,
		conn:       conn,
		profile:    profile,
		upstream:   upstream,
		statsID:    stats.ID,
		remoteAddr: remoteAddr,
	}
	hp.Handle()
}

func (s *Server) doHandshake(client net.Conn) error {
	br := bufio.NewReader(client)
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return err
	}
	if header[0] != 0x05 {
		return fmt.Errorf("bad version %d", header[0])
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	var chosen byte
	if s.cfg.AuthEnabled {
		authSupported := false
		for _, m := range methods {
			if m == 0x02 {
				authSupported = true
				break
			}
		}
		if !authSupported {
			client.Write([]byte{0x05, 0xFF})
			return fmt.Errorf("auth required but not offered")
		}
		if err := s.doAuth(client); err != nil {
			return err
		}
		chosen = 0x02
	} else {
		chosen = 0x00
	}
	if _, err := client.Write([]byte{0x05, chosen}); err != nil {
		return err
	}
	return nil
}

func (s *Server) doAuth(client net.Conn) error {
	br := bufio.NewReader(client)
	ver, err := br.ReadByte()
	if err != nil {
		return err
	}
	if ver != 0x01 {
		return fmt.Errorf("bad auth version %d", ver)
	}
	ulen, _ := br.ReadByte()
	user := make([]byte, ulen)
	io.ReadFull(br, user)
	plen, _ := br.ReadByte()
	pass := make([]byte, plen)
	io.ReadFull(br, pass)

	if string(user) == s.cfg.AuthUser && string(pass) == s.cfg.AuthPass {
		client.Write([]byte{0x01, 0x00})
		return nil
	}
	client.Write([]byte{0x01, 0x01})
	return fmt.Errorf("invalid credentials")
}

func (s *Server) readRequest(client net.Conn) (target string, cmd byte, err error) {
	br := bufio.NewReader(client)
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return "", 0, err
	}
	if req[0] != 0x05 {
		return "", 0, fmt.Errorf("bad version")
	}
	cmd = req[1]
	if cmd != 0x01 && cmd != 0x02 && cmd != 0x03 {
		return "", 0, fmt.Errorf("unsupported cmd %d", cmd)
	}
	if req[2] != 0x00 {
		return "", 0, fmt.Errorf("reserved byte not zero")
	}
	atyp := req[3]
	var host string
	switch atyp {
	case 0x01:
		ip := make([]byte, 4)
		io.ReadFull(br, ip)
		host = net.IP(ip).String()
	case 0x03:
		lenb, _ := br.ReadByte()
		name := make([]byte, lenb)
		io.ReadFull(br, name)
		host = string(name)
	case 0x04:
		ip := make([]byte, 16)
		io.ReadFull(br, ip)
		host = net.IP(ip).String()
	default:
		return "", 0, fmt.Errorf("unsupported address type %d", atyp)
	}
	portBytes := make([]byte, 2)
	io.ReadFull(br, portBytes)
	port := binary.BigEndian.Uint16(portBytes)
	target = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return target, cmd, nil
}

func (s *Server) sendReply(client net.Conn, rep byte) error {
	reply := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := client.Write(reply)
	return err
}

func (s *Server) proxyConnect(client net.Conn, remote, target string, profile *DeviceProfile, upstream *Upstream, stats *ConnStats) {
	var targetConn net.Conn
	var err error
	if upstream != nil {
		targetConn, err = dialUpstream(upstream, target)
	} else {
		targetConn, err = net.DialTimeout("tcp", target, 10*time.Second)
	}
	if err != nil {
		s.sendReply(client, 0x05)
		if s.cfg.Verbose {
			log.Printf("Connect %d: dial %s failed: %v", stats.ID, target, err)
		}
		return
	}
	defer targetConn.Close()
	if err := s.sendReply(client, 0x00); err != nil {
		return
	}
	lc := NewLatencyConn(client,
		time.Duration(s.cfg.LatencyMs)*time.Millisecond,
		time.Duration(s.cfg.JitterMs)*time.Millisecond,
		s.cfg.PacketLoss,
		s.cfg.BandwidthBps)
	var wg sync.WaitGroup
	wg.Add(2)
	buf1 := bufferPool.Get().([]byte)
	buf2 := bufferPool.Get().([]byte)
	defer func() {
		bufferPool.Put(buf1)
		bufferPool.Put(buf2)
	}()
	go func() {
		defer wg.Done()
		io.CopyBuffer(targetConn, lc, buf1)
		if tcp, ok := targetConn.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.CopyBuffer(lc, targetConn, buf2)
		lc.Close()
	}()
	wg.Wait()
	read, write := lc.Stats()
	s.tracker.Update(stats.ID, read, write)
	if s.cfg.Verbose {
		log.Printf("Connect %d: closed (read %d, write %d)", stats.ID, read, write)
	}
}

func (s *Server) proxyBind(client net.Conn, remote, target string, profile *DeviceProfile, upstream *Upstream, stats *ConnStats) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		s.sendReply(client, 0x05)
		return
	}
	defer listener.Close()
	addr := listener.Addr().(*net.TCPAddr)
	reply := []byte{0x05, 0x00, 0x00, 0x01}
	reply = append(reply, addr.IP.To4()...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(addr.Port))
	reply = append(reply, portBytes...)
	if _, err := client.Write(reply); err != nil {
		return
	}
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second))
	incoming, err := listener.Accept()
	if err != nil {
		s.sendReply(client, 0x06)
		return
	}
	defer incoming.Close()
	remoteAddr := incoming.RemoteAddr().(*net.TCPAddr)
	reply2 := []byte{0x05, 0x00, 0x00, 0x01}
	reply2 = append(reply2, remoteAddr.IP.To4()...)
	portBytes2 := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes2, uint16(remoteAddr.Port))
	reply2 = append(reply2, portBytes2...)
	if _, err := client.Write(reply2); err != nil {
		return
	}
	lc := NewLatencyConn(client,
		time.Duration(s.cfg.LatencyMs)*time.Millisecond,
		time.Duration(s.cfg.JitterMs)*time.Millisecond,
		s.cfg.PacketLoss,
		s.cfg.BandwidthBps)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(incoming, lc) }()
	go func() { defer wg.Done(); io.Copy(lc, incoming) }()
	wg.Wait()
}

func (s *Server) proxyUDPAssociate(client net.Conn, remote, target string, profile *DeviceProfile, upstream *Upstream, stats *ConnStats) {
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		s.sendReply(client, 0x05)
		return
	}
	defer udpConn.Close()
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	ip := localAddr.IP.To4()
	if ip == nil {
		ip = localAddr.IP
	}
	atyp := byte(0x01)
	if len(ip) == 16 {
		atyp = 0x04
	}
	reply := []byte{0x05, 0x00, 0x00, atyp}
	reply = append(reply, ip...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(localAddr.Port))
	reply = append(reply, portBytes...)
	client.Write(reply)
	buf := make([]byte, 1)
	for {
		client.SetReadDeadline(time.Now().Add(time.Duration(s.cfg.IdleTimeoutSec) * time.Second))
		_, err := client.Read(buf)
		if err != nil {
			return
		}
	}
}

func (s *Server) udpLoop() {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-cleanupTicker.C:
			s.udpNAT.Cleanup()
		default:
		}
		s.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Printf("UDP read error: %v", err)
				continue
			}
		}
		if n < 10 {
			continue
		}
		if target, ok := s.udpNAT.Get(clientAddr); ok {
			_, err := s.udpConn.WriteToUDP(buf[:n], target)
			if err != nil && s.cfg.Verbose {
				log.Printf("UDP response forward error: %v", err)
			}
			continue
		}
		if buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
			continue
		}
		var targetAddr string
		var offset int
		switch buf[3] {
		case 0x01:
			if n < 10 {
				continue
			}
			targetAddr = net.IP(buf[4:8]).String()
			offset = 10
		case 0x03:
			if n < 7 {
				continue
			}
			domainLen := int(buf[4])
			if n < 7+domainLen {
				continue
			}
			targetAddr = string(buf[5 : 5+domainLen])
			offset = 7 + domainLen
		case 0x04:
			if n < 22 {
				continue
			}
			targetAddr = "[" + net.IP(buf[4:20]).String() + "]"
			offset = 22
		default:
			continue
		}
		port := binary.BigEndian.Uint16(buf[offset-2 : offset])
		fullTarget := net.JoinHostPort(targetAddr, strconv.Itoa(int(port)))
		targetUDP, err := net.ResolveUDPAddr("udp", fullTarget)
		if err != nil {
			continue
		}
		data := buf[offset:n]
		if s.cfg.PacketLoss > 0 && rand.Float64() < s.cfg.PacketLoss {
			continue
		}
		if s.cfg.LatencyMs > 0 || s.cfg.JitterMs > 0 {
			jitter := time.Duration(0)
			if s.cfg.JitterMs > 0 {
				jitter = time.Duration(rand.Int63n(int64(s.cfg.JitterMs)*2)) - time.Duration(s.cfg.JitterMs)
			}
			sleep := time.Duration(s.cfg.LatencyMs)*time.Millisecond + jitter
			if sleep > 0 {
				time.Sleep(sleep)
			}
		}
		_, err = s.udpConn.WriteToUDP(data, targetUDP)
		if err != nil && s.cfg.Verbose {
			log.Printf("UDP forward to %s error: %v", fullTarget, err)
		}
		s.udpNAT.Set(clientAddr, targetUDP, 60*time.Second)
	}
}

func (s *Server) startHTTPAPI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/config", s.handleConfig)
	mux.HandleFunc("/connections", s.handleConnections)
	mux.HandleFunc("/set/latency", s.handleSetLatency)
	mux.HandleFunc("/set/jitter", s.handleSetJitter)
	mux.HandleFunc("/set/loss", s.handleSetLoss)
	mux.HandleFunc("/set/bandwidth", s.handleSetBandwidth)
	mux.HandleFunc("/profiles", s.handleProfiles)
	mux.HandleFunc("/upstreams", s.handleUpstreams)
	s.httpSrv = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.cfg.HTTPPort+1),
		Handler: mux,
	}
	go func() {
		log.Printf("HTTP API listening on http://localhost:%d", s.cfg.HTTPPort+1)
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP API error: %v", err)
		}
	}()
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status := map[string]interface{}{
		"running":       s.running,
		"port":          s.cfg.Port,
		"latency_ms":    s.cfg.LatencyMs,
		"jitter_ms":     s.cfg.JitterMs,
		"packet_loss":   s.cfg.PacketLoss,
		"bandwidth_bps": s.cfg.BandwidthBps,
		"active_conns":  s.tracker.Active(),
		"total_conns":   s.tracker.Total(),
	}
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	json.NewEncoder(w).Encode(s.cfg)
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	conns := s.tracker.All()
	json.NewEncoder(w).Encode(conns)
}

func (s *Server) handleSetLatency(w http.ResponseWriter, r *http.Request) {
	ms, err := strconv.Atoi(r.URL.Query().Get("ms"))
	if err != nil || ms < 0 {
		http.Error(w, "invalid ms", 400)
		return
	}
	s.mu.Lock()
	s.cfg.LatencyMs = ms
	s.mu.Unlock()
	w.Write([]byte("OK"))
}

func (s *Server) handleSetJitter(w http.ResponseWriter, r *http.Request) {
	ms, err := strconv.Atoi(r.URL.Query().Get("ms"))
	if err != nil || ms < 0 {
		http.Error(w, "invalid ms", 400)
		return
	}
	s.mu.Lock()
	s.cfg.JitterMs = ms
	s.mu.Unlock()
	w.Write([]byte("OK"))
}

func (s *Server) handleSetLoss(w http.ResponseWriter, r *http.Request) {
	loss, err := strconv.ParseFloat(r.URL.Query().Get("loss"), 64)
	if err != nil || loss < 0 || loss > 1 {
		http.Error(w, "loss must be 0-1", 400)
		return
	}
	s.mu.Lock()
	s.cfg.PacketLoss = loss
	s.mu.Unlock()
	w.Write([]byte("OK"))
}

func (s *Server) handleSetBandwidth(w http.ResponseWriter, r *http.Request) {
	bps, err := strconv.ParseInt(r.URL.Query().Get("bps"), 10, 64)
	if err != nil || bps < 0 {
		http.Error(w, "bps must be >=0", 400)
		return
	}
	s.mu.Lock()
	s.cfg.BandwidthBps = bps
	s.mu.Unlock()
	w.Write([]byte("OK"))
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.pm.RLock()
		defer s.pm.RUnlock()
		var list []*DeviceProfile
		for _, p := range s.pm.profiles {
			list = append(list, p)
		}
		json.NewEncoder(w).Encode(list)
	} else if r.Method == "POST" {
		var p DeviceProfile
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		s.pm.Lock()
		s.pm.profiles[p.Name] = &p
		s.pm.Unlock()
		w.WriteHeader(201)
	}
}

func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.pm.RLock()
		defer s.pm.RUnlock()
		json.NewEncoder(w).Encode(s.pm.upstreams)
	} else if r.Method == "POST" {
		var u Upstream
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		s.pm.Lock()
		s.pm.upstreams = append(s.pm.upstreams, u)
		s.pm.Unlock()
		w.WriteHeader(201)
	}
}

func printHelp() {
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("start                        - start proxy")
	fmt.Println("stop                         - stop proxy")
	fmt.Println("set <ms>                     - set latency (ms)")
	fmt.Println("jitter <ms>                  - set jitter (ms)")
	fmt.Println("loss <percent>               - set packet loss (0-100)")
	fmt.Println("bandwidth <bps>              - set bandwidth limit (bytes/s, 0 = unlimited)")
	fmt.Println("status                       - show status")
	fmt.Println("connections                  - list active connections")
	fmt.Println("config                       - show full config")
	fmt.Println("profile list                 - list device profiles")
	fmt.Println("upstream list                - list upstream proxies")
	fmt.Println("help                         - this help")
	fmt.Println("exit / quit                  - exit")
	fmt.Println()
}

func printConfig(cfg *Config) {
	fmt.Println("Current configuration:")
	fmt.Printf("Port:         %d\n", cfg.Port)
	fmt.Printf("UDP Port:     %d\n", cfg.UDPPort)
	fmt.Printf("UDP:          %v\n", cfg.UDPEnabled)
	fmt.Printf("HTTP Proxy:   %v (port %d)\n", cfg.HTTPEnabled, cfg.HTTPPort)
	fmt.Printf("Latency:      %d ms\n", cfg.LatencyMs)
	fmt.Printf("Jitter:       %d ms\n", cfg.JitterMs)
	fmt.Printf("Packet Loss:  %.1f%%\n", cfg.PacketLoss*100)
	fmt.Printf("Bandwidth:    %d bps", cfg.BandwidthBps)
	if cfg.BandwidthBps > 0 {
		fmt.Printf(" (%.2f Mbps)", float64(cfg.BandwidthBps)*8/1024/1024)
	} else {
		fmt.Print("(unlimited)")
	}
	fmt.Println()
	fmt.Printf("Max Conn:     %d\n", cfg.MaxConnections)
	fmt.Printf("Idle Timeout: %d s\n", cfg.IdleTimeoutSec)
	fmt.Printf("Auth:         %v\n", cfg.AuthEnabled)
	if cfg.AuthEnabled {
		fmt.Printf("User: %s\n", cfg.AuthUser)
	}
	if len(cfg.AllowedCIDRs) > 0 {
		fmt.Printf("Allowed CIDRs: %v\n", cfg.AllowedCIDRs)
	}
	if len(cfg.BlockedCIDRs) > 0 {
		fmt.Printf("Blocked CIDRs: %v\n", cfg.BlockedCIDRs)
	}
	fmt.Printf("Profiles:     %d\n", len(cfg.Profiles))
	fmt.Printf("Upstreams:    %d\n", len(cfg.Upstreams))
	fmt.Println()
}

func main() {
	cfg := DefaultConfig()
	configFile := flag.String("config", "", "path to JSON config file")
	port := flag.Int("port", cfg.Port, "SOCKS5 port")
	latency := flag.Int("latency", cfg.LatencyMs, "latency ms")
	jitter := flag.Int("jitter", cfg.JitterMs, "jitter ms")
	loss := flag.Float64("loss", cfg.PacketLoss, "packet loss 0-1")
	bandwidth := flag.Int64("bandwidth", cfg.BandwidthBps, "bandwidth bps")
	maxConns := flag.Int("max-conns", cfg.MaxConnections, "max connections")
	auth := flag.Bool("auth", cfg.AuthEnabled, "enable auth")
	authUser := flag.String("auth-user", cfg.AuthUser, "username")
	authPass := flag.String("auth-pass", cfg.AuthPass, "password")
	httpEnable := flag.Bool("http", cfg.HTTPEnabled, "enable HTTP proxy")
	httpPort := flag.Int("http-port", cfg.HTTPPort, "HTTP proxy port")
	verbose := flag.Bool("verbose", cfg.Verbose, "verbose logging")
	flag.Parse()
	setFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })
	if *configFile != "" {
		data, err := os.ReadFile(*configFile)
		if err != nil {
			log.Fatalf("read config: %v", err)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			log.Fatalf("parse config: %v", err)
		}
	}
	if setFlags["port"] {
		cfg.Port = *port
	}
	if setFlags["latency"] {
		cfg.LatencyMs = *latency
	}
	if setFlags["jitter"] {
		cfg.JitterMs = *jitter
	}
	if setFlags["loss"] {
		cfg.PacketLoss = *loss
	}
	if setFlags["bandwidth"] {
		cfg.BandwidthBps = *bandwidth
	}
	if setFlags["max-conns"] {
		cfg.MaxConnections = *maxConns
	}
	if setFlags["auth"] {
		cfg.AuthEnabled = *auth
	}
	if setFlags["auth-user"] {
		cfg.AuthUser = *authUser
	}
	if setFlags["auth-pass"] {
		cfg.AuthPass = *authPass
	}
	if setFlags["http"] {
		cfg.HTTPEnabled = *httpEnable
	}
	if setFlags["http-port"] {
		cfg.HTTPPort = *httpPort
	}
	if setFlags["verbose"] {
		cfg.Verbose = *verbose
	}
	rand.Seed(time.Now().UnixNano())
	server, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("create server: %v", err)
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Signal received, stopping...")
		server.Stop()
		os.Exit(0)
	}()
	fmt.Println("SOCKS5/HTTP Proxy with Device & Location Spoofing")
	fmt.Println("Type 'help' for commands.")
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		cmd := parts[0]
		switch cmd {
		case "start":
			if err := server.Start(); err != nil {
				fmt.Println("Error:", err)
			}
		case "stop":
			if err := server.Stop(); err != nil {
				fmt.Println("Error:", err)
			}
		case "set":
			if len(parts) != 2 {
				fmt.Println("Usage: set <ms>")
				continue
			}
			ms, err := strconv.Atoi(parts[1])
			if err != nil || ms < 0 {
				fmt.Println("Invalid ms")
				continue
			}
			server.mu.Lock()
			server.cfg.LatencyMs = ms
			server.mu.Unlock()
			fmt.Printf("Latency set to %d ms\n", ms)
		case "jitter":
			if len(parts) != 2 {
				fmt.Println("Usage: jitter <ms>")
				continue
			}
			ms, err := strconv.Atoi(parts[1])
			if err != nil || ms < 0 {
				fmt.Println("Invalid ms")
				continue
			}
			server.mu.Lock()
			server.cfg.JitterMs = ms
			server.mu.Unlock()
			fmt.Printf("Jitter set to %d ms\n", ms)
		case "loss":
			if len(parts) != 2 {
				fmt.Println("Usage: loss <percent>")
				continue
			}
			pct, err := strconv.ParseFloat(parts[1], 64)
			if err != nil || pct < 0 || pct > 100 {
				fmt.Println("Percent must be 0-100")
				continue
			}
			lossVal := pct / 100.0
			server.mu.Lock()
			server.cfg.PacketLoss = lossVal
			server.mu.Unlock()
			fmt.Printf("Packet loss set to %.1f%%\n", pct)
		case "bandwidth":
			if len(parts) != 2 {
				fmt.Println("Usage: bandwidth <bps>")
				continue
			}
			bps, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil || bps < 0 {
				fmt.Println("bps must be >=0")
				continue
			}
			server.mu.Lock()
			server.cfg.BandwidthBps = bps
			server.mu.Unlock()
			fmt.Printf("Bandwidth set to %d bps\n", bps)
		case "status":
			server.mu.RLock()
			running := server.running
			cfg := server.cfg
			active := server.tracker.Active()
			total := server.tracker.Total()
			server.mu.RUnlock()
			if running {
				fmt.Printf("Running on port %d, latency %dms, jitter %dms, loss %.1f%%, active %d, total %d\n",
					cfg.Port, cfg.LatencyMs, cfg.JitterMs, cfg.PacketLoss*100, active, total)
			} else {
				fmt.Println("Stopped")
			}
		case "connections":
			conns := server.tracker.All()
			if len(conns) == 0 {
				fmt.Println("No active connections")
			} else {
				fmt.Printf("Active connections (%d):\n", len(conns))
				for _, c := range conns {
					dur := time.Since(c.Start).Round(time.Second)
					fmt.Printf("  [%d] %s -> %s (%s, %s) profile=%s upstream=%s\n",
						c.ID, c.RemoteAddr, c.TargetAddr, c.Protocol, dur, c.Profile, c.Upstream)
				}
			}
		case "config":
			server.mu.RLock()
			printConfig(server.cfg)
			server.mu.RUnlock()
		case "profile":
			if len(parts) < 2 {
				fmt.Println("Usage: profile list")
				continue
			}
			if parts[1] == "list" {
				server.pm.RLock()
				for name := range server.pm.profiles {
					fmt.Println(name)
				}
				server.pm.RUnlock()
			} else {
				fmt.Println("Unknown profile subcommand")
			}
		case "upstream":
			if len(parts) < 2 {
				fmt.Println("Usage: upstream list")
				continue
			}
			if parts[1] == "list" {
				server.pm.RLock()
				for _, u := range server.pm.upstreams {
					fmt.Printf("%s (%s) weight=%d location=%s\n", u.Address, u.Type, u.Weight, u.Location)
				}
				server.pm.RUnlock()
			} else {
				fmt.Println("Unknown upstream subcommand")
			}
		case "help":
			printHelp()
		case "exit", "quit":
			server.Stop()
			fmt.Println("Goodbye.")
			return
		default:
			fmt.Println("Unknown command. Type 'help'.")
		}
	}
}
