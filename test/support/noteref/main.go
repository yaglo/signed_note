// Reference driver for differential testing against golang.org/x/mod/sumdb/note,
// the implementation the C2SP signed-note specification was extracted from.
//
// Batch protocol: tab-separated fields, base64 (std, padded) payloads, one
// request per line on stdin, one response per line on stdout.
//
//	genkeys <n> <name-prefix>
//	  emits n lines: skey \t vkey
//	sign
//	  stdin:  skey \t text_b64
//	  stdout: ok \t note_b64  |  err \t msg_b64
//	open
//	  stdin:  note_b64 \t vkey[,vkey...]  (vkey list may be empty)
//	  stdout: ok \t text_b64 \t name[,name...]  |  err \t kind \t msg_b64
//
// Error kinds for open: unverified (no known-key signature), invalid
// (known-key signature failed), malformed (structure), other.
package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

func b64(s []byte) string { return base64.StdEncoding.EncodeToString(s) }

func main() {
	switch os.Args[1] {
	case "genkeys":
		n, _ := strconv.Atoi(os.Args[2])
		prefix := os.Args[3]
		out := bufio.NewWriter(os.Stdout)
		defer out.Flush()
		for i := 0; i < n; i++ {
			skey, vkey, err := note.GenerateKey(nil, fmt.Sprintf("%s%d", prefix, i))
			if err != nil {
				panic(err)
			}
			fmt.Fprintf(out, "%s\t%s\n", skey, vkey)
		}
	case "sign":
		in := bufio.NewScanner(os.Stdin)
		in.Buffer(make([]byte, 0, 1<<20), 1<<24)
		out := bufio.NewWriter(os.Stdout)
		defer out.Flush()
		for in.Scan() {
			parts := strings.Split(in.Text(), "\t")
			signer, err := note.NewSigner(parts[0])
			if err != nil {
				fmt.Fprintf(out, "err\t%s\n", b64([]byte(err.Error())))
				continue
			}
			text, _ := base64.StdEncoding.DecodeString(parts[1])
			msg, err := note.Sign(&note.Note{Text: string(text)}, signer)
			if err != nil {
				fmt.Fprintf(out, "err\t%s\n", b64([]byte(err.Error())))
				continue
			}
			fmt.Fprintf(out, "ok\t%s\n", b64(msg))
		}
		if err := in.Err(); err != nil {
			// Exiting silently here would shorten the response set, which
			// the caller could read as agreement.
			fmt.Fprintf(os.Stderr, "scan: %v\n", err)
			os.Exit(3)
		}
	case "open":
		in := bufio.NewScanner(os.Stdin)
		in.Buffer(make([]byte, 0, 1<<20), 1<<24)
		out := bufio.NewWriter(os.Stdout)
		defer out.Flush()
		for in.Scan() {
			parts := strings.Split(in.Text(), "\t")
			msg, _ := base64.StdEncoding.DecodeString(parts[0])
			var verifiers []note.Verifier
			if len(parts) > 1 && parts[1] != "" {
				for _, vkey := range strings.Split(parts[1], ",") {
					v, err := note.NewVerifier(vkey)
					if err != nil {
						fmt.Fprintf(out, "err\tother\t%s\n", b64([]byte(err.Error())))
						continue
					}
					verifiers = append(verifiers, v)
				}
			}
			n, err := note.Open(msg, note.VerifierList(verifiers...))
			if err != nil {
				kind := "other"
				var unverified *note.UnverifiedNoteError
				var invalid *note.InvalidSignatureError
				switch {
				case errors.As(err, &unverified):
					kind = "unverified"
				case errors.As(err, &invalid):
					kind = "invalid"
				case strings.Contains(err.Error(), "malformed"):
					kind = "malformed"
				}
				fmt.Fprintf(out, "err\t%s\t%s\n", kind, b64([]byte(err.Error())))
				continue
			}
			names := make([]string, 0, len(n.Sigs))
			for _, sig := range n.Sigs {
				names = append(names, sig.Name)
			}
			fmt.Fprintf(out, "ok\t%s\t%s\n", b64([]byte(n.Text)), strings.Join(names, ","))
		}
		if err := in.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "scan: %v\n", err)
			os.Exit(3)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown mode")
		os.Exit(2)
	}
}
