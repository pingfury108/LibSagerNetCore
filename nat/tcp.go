package nat

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/Dreamacro/clash/common/cache"
	"github.com/sirupsen/logrus"
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"libcore/comm"
)

type tcpForwarder struct {
	tun      *SystemTun
	access   sync.Mutex
	port     uint16
	listener *net.TCPListener
	closed   bool
	sessions *cache.LruCache
}

func listenTcpForwarder(tun *SystemTun, port uint16) (*net.TCPListener, error) {
	var network string
	address := &net.TCPAddr{Port: int(port)}
	if tun.ipv6Mode == comm.IPv6Disable {
		network = "tcp4"
		address.IP = net.IP(vlanClient4)
	} else {
		network = "tcp"
		address.IP = net.IPv6zero
	}
	return net.ListenTCP(network, address)
}

func newTcpForwarder(tun *SystemTun) (*tcpForwarder, error) {
	listener, err := listenTcpForwarder(tun, 0)
	if err != nil {
		return nil, newError("failed to create tcp forwarder").Base(err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	port := uint16(addr.Port)
	newError("tcp forwarder started at ", addr).AtDebug().WriteToLog()
	return &tcpForwarder{
		tun:      tun,
		port:     port,
		listener: listener,
		sessions: cache.NewLRUCache(
			cache.WithAge(300),
			cache.WithUpdateAgeOnGet(),
		),
	}, nil
}

// accept takes the current listener safely (it can be swapped by relisten).
func (t *tcpForwarder) accept() (*net.TCPConn, error) {
	t.access.Lock()
	listener := t.listener
	closed := t.closed
	t.access.Unlock()
	if closed || listener == nil {
		return nil, net.ErrClosed
	}
	return listener.AcceptTCP()
}

// relisten replaces the listener after a socket-level failure. The same port is
// reused so the packet rewriting in processIPv4/processIPv6 keeps working.
func (t *tcpForwarder) relisten() error {
	t.access.Lock()
	defer t.access.Unlock()
	if t.closed {
		return net.ErrClosed
	}
	if t.listener != nil {
		_ = t.listener.Close()
		t.listener = nil
	}
	listener, err := listenTcpForwarder(t.tun, t.port)
	if err != nil {
		return err
	}
	t.listener = listener
	return nil
}

func (t *tcpForwarder) dispatch() (bool, error) {
	conn, err := t.accept()
	if err != nil {
		return true, err
	}
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if ip4 := addr.IP.To4(); ip4 != nil {
		addr.IP = ip4
	}
	key := peerKey{tcpip.Address(addr.IP), uint16(addr.Port)}
	var session *peerValue
	iSession, ok := t.sessions.Get(peerKey{key.destinationAddress, key.sourcePort})
	if ok {
		session = iSession.(*peerValue)
	} else {
		conn.Close()
		return false, newError("dropped unknown tcp session with source port ", key.sourcePort, " to destination address ", key.destinationAddress)
	}

	source := v2rayNet.Destination{
		Address: v2rayNet.IPAddress([]byte(session.sourceAddress)),
		Port:    v2rayNet.Port(key.sourcePort),
		Network: v2rayNet.Network_TCP,
	}
	destination := v2rayNet.Destination{
		Address: v2rayNet.IPAddress([]byte(key.destinationAddress)),
		Port:    v2rayNet.Port(session.destinationPort),
		Network: v2rayNet.Network_TCP,
	}

	go func() {
		t.tun.handler.NewConnection(source, destination, conn)
		time.Sleep(time.Second * 5)
		t.sessions.Delete(key)
	}()

	return false, nil
}

func (t *tcpForwarder) dispatchLoop() {
	var failures int
	for {
		stop, err := t.dispatch()
		if err == nil {
			failures = 0
			continue
		}
		if !stop {
			// non fatal (e.g. dropped unknown session)
			continue
		}
		if errors.Is(err, net.ErrClosed) {
			return
		}
		failures++
		e := newError("dispatch tcp conn failed").Base(err)
		if failures >= 5 {
			e.WriteToLog()
			t.Close()
			t.tun.errorHandler(e.String())
			return
		}
		// A stray close of the listener fd (see dispatchLoop in nat.go) shows up
		// here as EINVAL/EBADF. Rebinding the same port recovers the tunnel
		// instead of tearing down the whole VPN for a single transient error.
		e.AtDebug().WriteToLog()
		time.Sleep(time.Duration(failures) * 100 * time.Millisecond)
		if rerr := t.relisten(); rerr != nil {
			newError("failed to rebind tcp forwarder").Base(rerr).AtDebug().WriteToLog()
		}
	}
}

func (t *tcpForwarder) processIPv4(ipHdr header.IPv4, tcpHdr header.TCP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := tcpHdr.SourcePort()
	destinationPort := tcpHdr.DestinationPort()

	var session *peerValue

	if sourcePort != t.port {

		key := peerKey{destinationAddress, sourcePort}
		iSession, ok := t.sessions.Get(key)
		if ok {
			session = iSession.(*peerValue)
		} else {
			session = &peerValue{sourceAddress, destinationPort}
			t.sessions.Set(key, session)
		}

		ipHdr.SetSourceAddress(destinationAddress)
		ipHdr.SetDestinationAddress(vlanClient4)
		tcpHdr.SetDestinationPort(t.port)

	} else {

		iSession, ok := t.sessions.Get(peerKey{destinationAddress, destinationPort})
		if ok {
			session = iSession.(*peerValue)
		} else {
			logrus.Warn("unknown tcp session with source port ", destinationPort, " to destination address ", destinationAddress)
			return
		}
		ipHdr.SetSourceAddress(destinationAddress)
		tcpHdr.SetSourcePort(session.destinationPort)
		ipHdr.SetDestinationAddress(session.sourceAddress)
	}

	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.ChecksumCombine(
		header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), uint16(len(tcpHdr))),
		header.Checksum(tcpHdr.Payload(), 0),
	)))

	t.tun.writeBuffer(ipHdr)
}

func (t *tcpForwarder) processIPv6(ipHdr header.IPv6, tcpHdr header.TCP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := tcpHdr.SourcePort()
	destinationPort := tcpHdr.DestinationPort()

	var session *peerValue

	if sourcePort != t.port {

		key := peerKey{destinationAddress, sourcePort}
		iSession, ok := t.sessions.Get(key)
		if ok {
			session = iSession.(*peerValue)
		} else {
			session = &peerValue{sourceAddress, destinationPort}
			t.sessions.Set(key, session)
		}

		ipHdr.SetSourceAddress(destinationAddress)
		ipHdr.SetDestinationAddress(vlanClient6)
		tcpHdr.SetDestinationPort(t.port)

	} else {

		iSession, ok := t.sessions.Get(peerKey{destinationAddress, destinationPort})
		if ok {
			session = iSession.(*peerValue)
		} else {
			logrus.Warn("unknown tcp session with source port ", destinationPort, " to destination address ", destinationAddress)
			return
		}

		ipHdr.SetSourceAddress(destinationAddress)
		tcpHdr.SetSourcePort(session.destinationPort)
		ipHdr.SetDestinationAddress(session.sourceAddress)
	}

	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.ChecksumCombine(
		header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), uint16(len(tcpHdr))),
		header.Checksum(tcpHdr.Payload(), 0),
	)))

	t.tun.writeBuffer(ipHdr)
}

func (t *tcpForwarder) Close() error {
	t.access.Lock()
	defer t.access.Unlock()
	t.closed = true
	if t.listener == nil {
		return nil
	}
	err := t.listener.Close()
	t.listener = nil
	return err
}
