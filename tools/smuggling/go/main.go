// The other side of tools/smuggling/compare.py: Go's net/http reading the
// same request streams as our codec (tools/smuggling/codec.mojo). Each line
// of the file named by its argument is one stream, in hex; for each it
// prints one line: the requests it read, "METHOD TARGET BODYLEN" joined by
// "|", then "|error" if it stopped on an error rather than at the end.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		stream, err := hex.DecodeString(line)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad hex:", err)
			os.Exit(1)
		}
		var got []string
		br := bufio.NewReader(bytes.NewReader(stream))
		for {
			if _, err := br.Peek(1); err == io.EOF {
				break // (the stream ended between requests)
			}
			req, err := http.ReadRequest(br)
			if err != nil {
				got = append(got, "error")
				break
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				got = append(got, "error")
				break
			}
			got = append(got, fmt.Sprintf("%s %s %d", req.Method, req.RequestURI, len(body)))
		}
		fmt.Fprintln(out, strings.Join(got, "|"))
	}
}
