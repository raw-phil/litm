package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	bpf "github.com/raw-phil/litm/internal/bpf"
)

var stop sync.Once

type pipePair struct {
	reader *io.PipeReader
	writer *io.PipeWriter
}

// conn represents a network connection with associated input and output pipe pairs,
// the remote address, and a channel for HTTP requests received.
type conn struct {
	// Input pipe pair.
	// Represents incoming data from the connection.
	in pipePair

	// Output pipe pair.
	// Represents outgoing data to the connection.
	out pipePair

	// Remote address of the connection (h:p).
	remoteAddr string

	// Channel for HTTP requests received
	reqCh chan *http.Request
}

// litmInstace represents an instance of the application.
type litmInstace struct {
	// eventRbReader is the reader for the event ring buffer.
	// Its used to read events that eBPF programs send.
	// C_OPEN, C_CLOSE,DATA_IN, DATA_OUT
	eventRbReader *ringbuf.Reader

	// errorRbReader is the reader for the error ring buffer.
	// Monitors and handles errors captured in eBPF programs.
	errorRbReader *ringbuf.Reader

	// connInfoRbReader is the reader for the connection info ring buffer.
	// Used to read IP and PORT of connected clients.
	connInfoRbReader *ringbuf.Reader

	// connMap is the map of connections indexed by FD.
	// Keeps track of active network connections and their associated data.
	connMap map[int64]conn

	// resCh is the channel on which HTTP responses, along with their corresponding requests
	// (accessible via (*http.Response).Request), captured by LITM are sent.
	resCh chan *http.Response

	// Error channel where the error is sent when LITM stops with stopWithErr(err error)
	errorCh chan error

	// Signals when LITM stops. Read from errorCh to check if it stopped due to an error.
	done chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     *sync.WaitGroup
}

type Litm interface {
	Start() (<-chan *http.Response, <-chan error, <-chan struct{})
	Stop()

	rbEventConsumer()
	rbErrConsumer()
	handleOpen(fd int64)
	handleClose(fd int64)
	inDataToHttp(fd int64)
	outDataToHttp(fd int64)
	stopWithErr(err error)
	cleanup()
}

func NewLitm(eventRb *ebpf.Map, errorRb *ebpf.Map, connInfoRb *ebpf.Map) (Litm, error) {
	eventRbReader, err := ringbuf.NewReader(eventRb)
	if err != nil {
		return nil, fmt.Errorf("NewLitm(): ringbuf.NewReader(eventRb): %w", err)
	}

	errorRbReader, err := ringbuf.NewReader(errorRb)
	if err != nil {
		return nil, fmt.Errorf("NewLitm(): ringbuf.NewReader(errorRb): %w", err)
	}

	connInfoRbReader, err := ringbuf.NewReader(connInfoRb)
	if err != nil {
		return nil, fmt.Errorf("NewLitm(): ringbuf.NewReader(connInfoRb): %w", err)
	}

	return &litmInstace{
		eventRbReader:    eventRbReader,
		errorRbReader:    errorRbReader,
		connInfoRbReader: connInfoRbReader,
		connMap:          make(map[int64]conn),
	}, nil
}

func (l *litmInstace) Start() (<-chan *http.Response, <-chan error, <-chan struct{}) {
	var wg sync.WaitGroup
	l.ctx, l.cancel = context.WithCancel(context.Background())
	l.wg = &wg
	l.errorCh = make(chan error, 1)
	l.resCh = make(chan *http.Response)
	l.done = make(chan struct{})

	go func() {
		<-l.ctx.Done()
		l.eventRbReader.Close()
		l.connInfoRbReader.Close()
		l.errorRbReader.Close()
		l.cleanup()
	}()

	l.rbEventConsumer()
	l.rbErrConsumer()

	return l.resCh, l.errorCh, l.done
}

func (l *litmInstace) Stop() {
	stop.Do(func() {
		l.cancel()
		l.wg.Wait()
		close(l.errorCh)
		close(l.done)
	})
}

func (l *litmInstace) rbEventConsumer() {
	l.wg.Add(1)

	go func() {

		defer l.wg.Done()
		defer close(l.resCh)

		var record ringbuf.Record
		for {
			err := l.eventRbReader.ReadInto(&record)
			if err != nil {
				select {
				case <-l.ctx.Done():
					return
				default:
					go l.stopWithErr(fmt.Errorf("rbEventConsumer(): reading from RingBuf: %w", err))
					return
				}
			}

			var eventType bpf.EventType
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &eventType); err != nil {
				go l.stopWithErr(fmt.Errorf("rbEventConsumer(): parsing EventType: %w", err))
				return
			}

			switch eventType {
			case bpf.C_OPEN:
				var connEvent bpf.ConnEvent
				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &connEvent); err != nil {
					go l.stopWithErr(fmt.Errorf("rbEventConsumer(): parsing ConnEvent: %w", err))
					return
				}
				l.handleOpen(connEvent.Fd)

			case bpf.C_CLOSE:
				var connEvent bpf.ConnEvent
				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &connEvent); err != nil {
					go l.stopWithErr(fmt.Errorf("rbEventConsumer(): parsing ConnEvent: %w", err))
					return
				}
				l.handleClose(connEvent.Fd)

			case bpf.DATA_IN:
				var dataEvent bpf.DataEvent
				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &dataEvent); err != nil {
					go l.stopWithErr(fmt.Errorf("rbEventConsumer(): parsing DataEvent: %w", err))
					return
				}

				if conn, ok := l.connMap[dataEvent.Fd]; ok {
					select {
					case <-l.ctx.Done():
						return
					default:
						conn.in.writer.Write(dataEvent.Buf[:dataEvent.Size])
					}
				} else {
					go l.stopWithErr(fmt.Errorf("rbEventConsumer(): write to closed conn"))
					return
				}

			case bpf.DATA_OUT:
				var dataEvent bpf.DataEvent
				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &dataEvent); err != nil {
					go l.stopWithErr(fmt.Errorf("rbEventConsumer(): parsing DataEvent: %w", err))
					return
				}

				if conn, ok := l.connMap[dataEvent.Fd]; ok {
					select {
					case <-l.ctx.Done():
						return
					default:
						conn.out.writer.Write(dataEvent.Buf[:dataEvent.Size])
					}
				} else {
					go l.stopWithErr(fmt.Errorf("rbEventConsumer(): write to closed conn"))
					return
				}

			default:
				go l.stopWithErr(fmt.Errorf("rbEventConsumer(): unknown event type: %d", eventType))
				return
			}
		}
	}()
}

func (l *litmInstace) rbErrConsumer() {
	l.wg.Add(1)

	go func() {
		defer l.wg.Done()

		var bpfErr bpf.RbError
		record, err := l.errorRbReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			go l.stopWithErr(fmt.Errorf("handleErrorEventsRb(): reading from RingBuf: %w", err))
			return
		}

		// Parse the ringbuf event entry into a bpf.RbError structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &bpfErr); err != nil {
			go l.stopWithErr(fmt.Errorf("handleErrorEventsRb(): parsing RingBuf event: %w", err))
			return
		}

		zeroIndex := bytes.IndexByte(bpfErr.Description[:], 0)
		go l.stopWithErr(fmt.Errorf("bpf_error: code='%d',  description='%s'", bpfErr.Code, bpfErr.Description[:zeroIndex]))
	}()
}

func (l *litmInstace) handleOpen(fd int64) {

	if _, ok := l.connMap[fd]; ok {
		go l.stopWithErr(fmt.Errorf("handleOpen(): open of a not closed conn"))
		return
	}

	inPipeReader, inPipeWriter := io.Pipe()
	outPipeReader, outPipeWriter := io.Pipe()

	l.connInfoRbReader.SetDeadline(time.Now().Add(1 * time.Second))

	connInfoRecod, err := l.connInfoRbReader.Read()
	if err != nil {
		select {
		case <-l.ctx.Done():
			return
		default:
			go l.stopWithErr(fmt.Errorf("handleOpen(): %w", err))
			return
		}
	}

	var connInfoEvent bpf.ConnInfoEvent
	if err := binary.Read(bytes.NewBuffer(connInfoRecod.RawSample), binary.NativeEndian, &connInfoEvent); err != nil {
		go l.stopWithErr(fmt.Errorf("handleOpen(): parsing EventType: %w", err))
		return
	}

	var sAddr string

	if connInfoEvent.Family == bpf.AF_INET {
		sAddr = net.IP(connInfoEvent.Saddr[:4]).String()
	} else if connInfoEvent.Family == bpf.AF_INET6 {
		sAddr = fmt.Sprintf("[%s]", net.IP(connInfoEvent.Saddr[:16]).String())
	} else {
		go l.stopWithErr(fmt.Errorf("handleOpen(): unkniwn connInfoEvent.Family"))
		return
	}

	l.connMap[fd] = conn{
		in: pipePair{
			reader: inPipeReader, writer: inPipeWriter,
		},
		out: pipePair{
			reader: outPipeReader, writer: outPipeWriter,
		},
		remoteAddr: fmt.Sprintf("%s:%d", sAddr, connInfoEvent.Sport),
		reqCh:      make(chan *http.Request),
	}

	l.inDataToHttp(fd)
	l.outDataToHttp(fd)
}

func (l *litmInstace) handleClose(fd int64) {
	if conn, ok := l.connMap[fd]; ok {
		conn.in.writer.Close()
		conn.out.writer.Close()
		delete(l.connMap, fd)
	} else {
		go l.stopWithErr(fmt.Errorf("handleClose(): close without open"))
	}
}

func (l *litmInstace) inDataToHttp(fd int64) {

	conn, ok := l.connMap[fd]
	if !ok {
		go l.stopWithErr(fmt.Errorf("inDataToHttp(): conn not found for %d fd", fd))
		return
	}

	l.wg.Add(1)

	go func() {

		defer l.wg.Done()
		defer close(conn.reqCh)

		bufReader := bufio.NewReader(conn.in.reader)
		for {
			req, err := http.ReadRequest(bufReader)

			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return
				}
				select {
				case <-l.ctx.Done():
					return
				default:
					// Should be some kind of warning, It does't block LITM
					fmt.Fprintf(os.Stderr, "error: inDataToHttp(): http.ReadResponse(): %v\n", err)
					continue
				}
			}

			req.RemoteAddr = conn.remoteAddr

			_, err = io.ReadAll(req.Body)
			if err != nil {
				// If server not read all the body
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					go l.stopWithErr(fmt.Errorf("inDataToHttp(): read body: %w", err))
					return
				}
			}

			req.Body.Close()

			select {
			case conn.reqCh <- req:
			case <-l.ctx.Done():
			}

		}
	}()
}

func (l *litmInstace) outDataToHttp(fd int64) {
	conn, ok := l.connMap[fd]
	if !ok {
		go l.stopWithErr(fmt.Errorf("outDataToHttp(): conn not found for %d fd", fd))
		return
	}

	l.wg.Add(1)

	go func() {

		defer l.wg.Done()

		bufReader := bufio.NewReader(conn.out.reader)
		for {
			res, err := http.ReadResponse(bufReader, nil)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return
				}
				select {
				case <-l.ctx.Done():
					return
				default:
					// Should be some kind of warning, It does't block LITM
					fmt.Fprintf(os.Stderr, "error: outDataToHttp(): http.ReadResponse(): %v", err)
					continue
				}
			}

			_, err = io.ReadAll(res.Body)
			if err != nil {
				// For handling HEAD
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					go l.stopWithErr(fmt.Errorf("outDataToHttp(): read body: %w", err))
					return
				}
			}
			res.Body.Close()

			req, ok := <-conn.reqCh
			if !ok {
				continue
			}
			res.Request = req

			select {
			case l.resCh <- res:
			case <-l.ctx.Done():
			}
		}
	}()
}

func (l *litmInstace) stopWithErr(err error) {
	stop.Do(func() {
		select {
		case l.errorCh <- err:
		default:
		}
		close(l.errorCh)

		l.cancel()
		l.wg.Wait()
		close(l.done)
	})
}

func (l *litmInstace) cleanup() {
	for _, connection := range l.connMap {
		connection.in.reader.Close()
		connection.in.writer.Close()
		connection.out.reader.Close()
		connection.out.writer.Close()
	}
}

// LogFormat defines the NCSA Common Log Format with Virtual Host
func ClfLog(r *http.Response) error {
	if r == nil || r.Request == nil {
		return fmt.Errorf("ClfLog(): Received nil response or request")
	}

	vhost := r.Request.Host
	ip, _, err := net.SplitHostPort(r.Request.RemoteAddr)
	if err != nil {
		ip = r.Request.RemoteAddr // Fallback to the full address if SplitHostPort fails
	}
	timestamp := time.Now().Format("02/Jan/2006:15:04:05 -0700")
	method := r.Request.Method
	uri := r.Request.URL.RequestURI()
	protocol := r.Proto
	status := r.StatusCode
	size := r.ContentLength
	if size == -1 {
		size = 0
	}

	fmt.Printf("%s %s - - [%s] \"%s %s %s\" %d %d\n", vhost, ip, timestamp, method, uri, protocol, status, size)
	return nil
}
