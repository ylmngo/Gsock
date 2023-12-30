package main

import (
	"fmt"
	"gsock/gsock"
	"net/http"
)

var connections map[*gsock.WebSock]bool = make(map[*gsock.WebSock]bool)

func main() {
	http.HandleFunc("/client", clientHandler)
	http.HandleFunc("/server", serverHandler)
	http.ListenAndServe(":8000", nil)
}

func clientHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "client.html")
}

func serverHandler(w http.ResponseWriter, r *http.Request) {
	wsock, err := gsock.Accept(w, r)
	if err != nil {
		fmt.Printf("Unable to upgrade HTTP Connection: %v\n", err)
		return
	}
	defer wsock.Close()

	connections[&wsock] = true

	ch := make(chan string)

	go func() {
		for {
			msg, err := wsock.Read()
			if err != nil {
				fmt.Printf("Unable to read from websocket connection: %v\n", err)
				return
			}
			ch <- msg
		}
	}()

	for {
		if msg := <-ch; msg != "" {
			for connection, ok := range connections {
				if ok {
					connection.Send(msg)
				}
			}
		}
	}
}
