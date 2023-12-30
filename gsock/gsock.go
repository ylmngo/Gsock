package gsock

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
)

const (
	wsMagic         = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	textHeadUpgrade = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
)

// WebSock encapsulates a websocket connection
type WebSock struct {
	conn   net.Conn
	buffrw *bufio.ReadWriter
}

// Accepts the incoming request and upgrades the connection to websocket
func Accept(w http.ResponseWriter, r *http.Request) (WebSock, error) {
	conn, buffrw, err := hijack(w)
	if err != nil {
		conn.Close()
		return WebSock{}, err
	}

	nonce, err := parseHeader(r.Header)
	if err != nil {
		conn.Close()
		return WebSock{}, err
	}

	accept := genSecWSAccept(nonce)
	response := buildResponse(accept)

	buffrw.Write([]byte(response))
	buffrw.Flush()

	wsock := WebSock{
		conn:   conn,
		buffrw: buffrw,
	}

	return wsock, nil
}

func hijack(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, error) {
	hj, _ := w.(http.Hijacker)
	conn, buffrw, err := hj.Hijack()
	return conn, buffrw, err
}

// Parses the request header and returns the underlying websocket key
// Errors if the header contains incorect values for Upgrade, Connection or WebSocket Version
func parseHeader(header http.Header) (string, error) {
	if header.Get("Upgrade") != "websocket" {
		return "", errors.New("bad handshake request: upgrade != websocket")
	}
	if header.Get("Connection") != "Upgrade" {
		return "", errors.New("bad handshake request: connection != upgrade")
	}
	if wsv, _ := strconv.Atoi(header.Get("Sec-WebSocket-Version")); wsv != 13 {
		return "", errors.New("bad handshake request: sec-websocket-version != 13")
	}

	return header.Get("Sec-WebSocket-Key"), nil
}

// Combines WebSocketKey and wsMagic in a hash and returns it's string equivalent
func genSecWSAccept(key string) string {
	hash := sha1.New()
	hash.Write([]byte(key))
	hash.Write([]byte(wsMagic))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func buildResponse(accept string) string {
	response := fmt.Sprintf("%sSec-WebSocket-Accept: %s\r\n\r\n", textHeadUpgrade, accept)
	return response
}

// ============= WebSock Functions ====================

func (wsock *WebSock) Close() {
	wsock.conn.Close()
}

func (wsock *WebSock) Read() (string, error) {
	frame, err := buildFrame(wsock.conn)
	if err != nil {
		return "", err
	}
	return string(frame.Payload), nil
}

func (wsock *WebSock) Send(msg string) error {
	if len(msg) > 125 {
		return errors.New("unsupported payload size")
	}

	frame := Frame{
		Fin:        true,
		Rsv1:       false,
		Rsv2:       false,
		Rsv3:       false,
		Opcode:     TEXT_FRAME,
		Payloadlen: len(msg),
	}

	header := frame.packFrame()

	wsock.buffrw.Write(header)
	wsock.buffrw.Write([]byte(msg))
	wsock.buffrw.Flush()

	return nil
}
