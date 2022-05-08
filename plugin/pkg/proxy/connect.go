// Package proxy implements a forwarding proxy. It caches an upstream net.Conn for some time, so if the same
// client returns the upstream's Conn will be precached. Depending on how you benchmark this looks to be
// 50% faster than just opening a new connection for every client. It works with UDP and TCP and uses
// inband healthchecking.
package proxy

import (
	"context"
	"io"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// limitTimeout is a utility function to auto-tune timeout values
// average observed time is moved towards the last observed delay moderated by a weight
// next timeout to use will be the double of the computed average, limited by min and max frame.
func limitTimeout(currentAvg *int64, minValue time.Duration, maxValue time.Duration) time.Duration {
	rt := time.Duration(atomic.LoadInt64(currentAvg))
	if rt < minValue {
		return minValue
	}
	if rt < maxValue/2 {
		return 2 * rt
	}
	return maxValue
}

func averageTimeout(currentAvg *int64, observedDuration time.Duration, weight int64) {
	dt := time.Duration(atomic.LoadInt64(currentAvg))
	atomic.AddInt64(currentAvg, int64(observedDuration-dt)/weight)
}

func (t *Transport) dialTimeout() time.Duration {
	return limitTimeout(&t.avgDialTime, minDialTimeout, maxDialTimeout)
}

func (t *Transport) updateDialTimeout(newDialTime time.Duration) {
	averageTimeout(&t.avgDialTime, newDialTime, cumulativeAvgWeight)
}

// Dial dials the address configured in transport, potentially reusing a connection or creating a new one.
func (t *Transport) Dial(proto string) (*persistConn, bool, error) {
	// If tls has been configured; use it.
	if t.tlsConfig != nil {
		proto = "tcp-tls"
	}

	t.dial <- proto
	pc := <-t.ret

	if pc != nil {
		connCacheHitsCount.WithLabelValues(t.proxyName, t.addr, proto).Add(1)
		return pc, true, nil
	}
	connCacheMissesCount.WithLabelValues(t.proxyName, t.addr, proto).Add(1)

	reqTime := time.Now()
	timeout := t.dialTimeout()
	if proto == "tcp-tls" {
		conn, err := dns.DialTimeoutWithTLS("tcp", t.addr, t.tlsConfig, timeout)
		t.updateDialTimeout(time.Since(reqTime))
		return &persistConn{c: conn}, false, err
	}
	conn, err := dns.DialTimeout(proto, t.addr, timeout)
	t.updateDialTimeout(time.Since(reqTime))
	return &persistConn{c: conn}, false, err
}

// Connect selects an upstream, sends the request and waits for a response.
func (p *Proxy) Connect(ctx context.Context, state request.Request, opts Options) (*dns.Msg, []dns.RR, error) {
	start := time.Now()

	proto := ""
	switch {
	case opts.ForceTCP: // TCP flag has precedence over UDP flag
		proto = "tcp"
	case opts.PreferUDP:
		proto = "udp"
	default:
		proto = state.Proto()
	}

	pc, cached, err := p.transport.Dial(proto)
	if err != nil {
		return nil, nil, err
	}

	// Set buffer size correctly for this client.
	pc.c.UDPSize = uint16(state.Size())
	if pc.c.UDPSize < 512 {
		pc.c.UDPSize = 512
	}

	var retRRs []dns.RR
	var ret *dns.Msg

	if state.QType() == dns.TypeAXFR || state.QType() == dns.TypeIXFR {
		pc.c.SetWriteDeadline(time.Now().Add(maxTimeout))
		if err := pc.c.WriteMsg(state.Req); err != nil {
			pc.c.Close() // not giving it back
			if err == io.EOF && cached {
				return nil, nil, ErrCachedClosed
			}
			return nil, nil, err
		}
		first := true
		for {
			pc.c.SetReadDeadline(time.Now().Add(p.readTimeout))
			in, err := pc.c.ReadMsg()
			if err != nil {
				pc.c.Close() // not giving it back
				if err == io.EOF && cached {
					return nil, nil, ErrCachedClosed
				}
				return ret, nil, err
			}
			if state.Req.Id != in.Id {
				// out-of-order response. unexpected.
				continue
			}
			if first {
				if len(in.Answer) == 0 || in.Answer[0].Header().Rrtype != dns.TypeSOA {
					pc.c.Close()
					return nil, nil, dns.ErrSoa
				}
				first = !first
				if len(in.Answer) == 1 {
					retRRs = append(retRRs, in.Answer[0])
					continue
				}
			}
			for _, rr := range in.Answer {
				retRRs = append(retRRs, rr)
			}
			if len(in.Answer) >= 0 && in.Answer[len(in.Answer)-1].Header().Rrtype == dns.TypeSOA {
				break
			}
		}
		p.transport.Yield(pc)
		return nil, retRRs, nil
	}

	pc.c.SetWriteDeadline(time.Now().Add(maxTimeout))
	// records the origin Id before upstream.
	originId := state.Req.Id
	state.Req.Id = dns.Id()
	defer func() {
		state.Req.Id = originId
	}()

	if err := pc.c.WriteMsg(state.Req); err != nil {
		pc.c.Close() // not giving it back
		if err == io.EOF && cached {
			return nil, nil, ErrCachedClosed
		}
		return nil, nil, err
	}

	pc.c.SetReadDeadline(time.Now().Add(p.readTimeout))
	for {
		ret, err = pc.c.ReadMsg()
		if err != nil {
			pc.c.Close() // not giving it back
			if err == io.EOF && cached {
				return nil, nil, ErrCachedClosed
			}
			// recovery the origin Id after upstream.
			if ret != nil {
				ret.Id = originId
			}
			return ret, nil, err
		}
		// drop out-of-order responses
		if state.Req.Id == ret.Id {
			break
		}
	}
	// recovery the origin Id after upstream.
	ret.Id = originId

	p.transport.Yield(pc)

	rc, ok := dns.RcodeToString[ret.Rcode]
	if !ok {
		rc = strconv.Itoa(ret.Rcode)
	}

	requestDuration.WithLabelValues(p.proxyName, p.addr, rc).Observe(time.Since(start).Seconds())

	return ret, nil, nil
}

const cumulativeAvgWeight = 4
