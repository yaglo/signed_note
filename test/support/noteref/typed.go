// Differential driver for the signature types beyond Ed25519, checked
// against github.com/transparency-dev/formats/note — the implementation
// c2sp.org/signed-note points to for ECDSA (0x02), and the one that
// implements the cosignature (0x04, 0x06) and RFC 6962 (0x05) types.
//
// That package verifies all four but signs only the two cosignature
// types, so 0x02 and 0x05 are signed here from crypto/ecdsa directly.
// Their reference verifiers still judge the result, and still recompute
// the key IDs, which is what these tests are for.
//
// Batch protocol, extending the one in main.go:
//
//	gentyped <n> <type> <name-prefix>
//	  emits n lines: skey \t vkey
//	signtyped
//	  stdin:  type \t skey \t text_b64 \t timestamp
//	  stdout: ok \t note_b64  |  err \t msg_b64
//	opentyped
//	  stdin:  note_b64 \t vkey[,vkey...]
//	  stdout: ok \t text_b64 \t name[,name...]  |  err \t kind \t msg_b64
//
//	sthverify
//	  stdin:  vkey \t note_b64
//	  stdout: ok \t timestamp  |  err \t msg_b64
//	subtreesign
//	  stdin:  skey \t origin \t start \t end \t hash_b64 \t timestamp
//	  stdout: ok \t sig_b64  |  err \t msg_b64
//	subtreeverify
//	  stdin:  vkey \t origin \t start \t end \t hash_b64 \t timestamp \t sig_b64
//	  stdout: ok \t  |  err \t msg_b64
//
// <type> is one of ecdsa, cosigv1, rfc6962, rfc6962rsa, mldsa. The
// timestamp field is used by the two types signed here; the reference
// cosignature signer stamps the current time itself and ignores it.
//
// RFC 6962 permits RSA log keys, which transparency-dev's verifier
// rejects, so sthverify is an independent reading of static-ct-api's
// framing and RFC 6962's TreeHeadSignature that judges both key kinds.
package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	tdnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

const (
	algECDSA   = 0x02
	algCosigV1 = 0x04
	algRFC6962 = 0x05
	algMLDSA   = 0x06
)

// Sizes of the fixed-width prefixes a note signature body carries.
const (
	keyHashSize   = 4
	timestampSize = 8
)

// typedMain handles the modes above, and reports whether it recognized
// one so main can keep its own default.
func typedMain(mode string) bool {
	switch mode {
	case "gentyped":
		n, _ := strconv.Atoi(os.Args[2])
		genTyped(n, os.Args[3], os.Args[4])
	case "signtyped":
		signTyped()
	case "opentyped":
		openTyped()
	case "sthverify":
		sthVerify()
	case "subtreesign":
		subtreeSign()
	case "subtreeverify":
		subtreeVerify()
	default:
		return false
	}
	return true
}

func genTyped(n int, typ, prefix string) {
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%s%d", prefix, i)
		skey, vkey, err := generateKey(typ, name)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(out, "%s\t%s\n", skey, vkey)
	}
}

func generateKey(typ, name string) (string, string, error) {
	switch typ {
	case "mldsa":
		return tdnote.GenerateMLDSAKey(name)
	case "cosigv1":
		// The reference generates a 0x01 key and restates it as 0x04;
		// the two share key material and differ in key ID.
		skey, vkey, err := note.GenerateKey(rand.Reader, name)
		if err != nil {
			return "", "", err
		}
		cosigVkey, err := tdnote.VKeyToCosignatureV1(vkey)
		if err != nil {
			return "", "", err
		}
		return skey, cosigVkey, nil
	case "ecdsa", "rfc6962":
		return generateECDSAKey(typ, name)
	case "rfc6962rsa":
		return generateRSAKey(name)
	default:
		return "", "", fmt.Errorf("unknown type %q", typ)
	}
}

// generateRSAKey makes the other kind of log key RFC 6962 Section 2.1.4
// allows. transparency-dev's verifier rejects these, so they exist to be
// checked against sthVerify below.
func generateRSAKey(name string) (string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	pkcs1 := x509.MarshalPKCS1PrivateKey(key)
	id := keyID(algRFC6962, name, spki)
	skey := fmt.Sprintf("PRIVATE+KEY+%s+%s+%s", name, id, b64(append([]byte{algRFC6962}, pkcs1...)))
	vkey := fmt.Sprintf("%s+%s+%s", name, id, b64(append([]byte{algRFC6962}, spki...)))
	return skey, vkey, nil
}

func generateECDSAKey(typ, name string) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	alg := byte(algECDSA)
	if typ == "rfc6962" {
		alg = algRFC6962
	}
	id := keyID(alg, name, spki)
	skey := fmt.Sprintf("PRIVATE+KEY+%s+%s+%s", name, id, b64(append([]byte{alg}, sec1...)))
	vkey := fmt.Sprintf("%s+%s+%s", name, id, b64(append([]byte{alg}, spki...)))
	return skey, vkey, nil
}

// keyID renders the hex key ID for a type whose key material is a SPKI
// DER: ECDSA hashes the DER alone, RFC 6962 hashes the name and the LogID.
func keyID(alg byte, name string, spki []byte) string {
	if alg == algECDSA {
		sum := sha256.Sum256(spki)
		return fmt.Sprintf("%08x", binary.BigEndian.Uint32(sum[:]))
	}
	logID := sha256.Sum256(spki)
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0x0A, algRFC6962})
	h.Write(logID[:])
	return fmt.Sprintf("%08x", binary.BigEndian.Uint32(h.Sum(nil)))
}

func signTyped() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 1<<24)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		parts := strings.Split(in.Text(), "\t")
		text, _ := base64.StdEncoding.DecodeString(parts[2])
		timestamp, _ := strconv.ParseUint(parts[3], 10, 64)
		msg, err := signOne(parts[0], parts[1], string(text), timestamp)
		if err != nil {
			fmt.Fprintf(out, "err\t%s\n", b64([]byte(err.Error())))
			continue
		}
		fmt.Fprintf(out, "ok\t%s\n", b64(msg))
	}
	if err := in.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "scan: %v\n", err)
		os.Exit(3)
	}
}

func signOne(typ, skey, text string, timestamp uint64) ([]byte, error) {
	switch typ {
	case "cosigv1", "mldsa":
		signer, err := tdnote.NewSignerForCosignatureV1(skey)
		if err != nil {
			return nil, err
		}
		return note.Sign(&note.Note{Text: text}, signer)
	case "ecdsa", "rfc6962":
		return signECDSANote(typ, skey, text, timestamp)
	case "rfc6962rsa":
		return signRSANote(skey, text, timestamp)
	default:
		return nil, fmt.Errorf("unknown type %q", typ)
	}
}

// signRSANote signs a checkpoint with an RSA log key, declaring rsa(1) in
// the digitally-signed struct as RFC 5246 Section 7.4.1.4.1 requires.
func signRSANote(skey, text string, timestamp uint64) ([]byte, error) {
	name, id, blob, err := parseSkey(skey)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(blob)
	if err != nil {
		return nil, err
	}
	sth, err := treeHeadSignatureBytes(name, timestamp, text)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(sth)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, err
	}
	body := binary.BigEndian.AppendUint64(nil, timestamp)
	body = append(body, 0x04, 0x01) // sha256, rsa
	body = binary.BigEndian.AppendUint16(body, uint16(len(signature)))
	body = append(body, signature...)

	line := fmt.Sprintf("— %s %s\n", name, b64(append(id, body...)))
	return []byte(text + "\n" + line), nil
}

func signECDSANote(typ, skey, text string, timestamp uint64) ([]byte, error) {
	name, id, key, err := parseECDSASkey(skey)
	if err != nil {
		return nil, err
	}
	var body []byte
	if typ == "ecdsa" {
		digest := sha256.Sum256([]byte(text))
		body, err = ecdsa.SignASN1(rand.Reader, key, digest[:])
	} else {
		body, err = signSTH(name, key, text, timestamp)
	}
	if err != nil {
		return nil, err
	}
	sig := append(id, body...)
	line := fmt.Sprintf("— %s %s\n", name, b64(sig))
	return []byte(text + "\n" + line), nil
}

// signSTH builds the RFC 6962 TreeHeadSignature over the checkpoint in
// text and frames it as the note signature static-ct-api specifies:
// uint64 timestamp followed by a TLS digitally-signed struct.
func signSTH(name string, key *ecdsa.PrivateKey, text string, timestamp uint64) ([]byte, error) {
	lines := strings.Split(text, "\n")
	if len(lines) != 4 || lines[3] != "" {
		return nil, errors.New("not a three-line checkpoint")
	}
	if lines[0] != name {
		return nil, errors.New("origin does not match the key name")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return nil, err
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, err
	}
	if len(root) != sha256.Size {
		return nil, errors.New("root hash is not 32 bytes")
	}

	sth := make([]byte, 0, 2+8+8+sha256.Size)
	sth = append(sth, 0x00, 0x01) // v1, tree_hash
	sth = binary.BigEndian.AppendUint64(sth, timestamp)
	sth = binary.BigEndian.AppendUint64(sth, size)
	sth = append(sth, root...)

	digest := sha256.Sum256(sth)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}

	body := binary.BigEndian.AppendUint64(nil, timestamp)
	body = append(body, 0x04, 0x03) // sha256, ecdsa
	body = binary.BigEndian.AppendUint16(body, uint16(len(signature)))
	return append(body, signature...), nil
}

func parseECDSASkey(skey string) (string, []byte, *ecdsa.PrivateKey, error) {
	name, id, blob, err := parseSkey(skey)
	if err != nil {
		return "", nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(blob)
	if err != nil {
		return "", nil, nil, err
	}
	return name, id, key, nil
}

// parseSkey splits a private key string into its name, key ID and the
// private key bytes after the signature type byte.
func parseSkey(skey string) (string, []byte, []byte, error) {
	parts := strings.SplitN(strings.TrimPrefix(skey, "PRIVATE+KEY+"), "+", 3)
	if len(parts) != 3 {
		return "", nil, nil, errors.New("malformed private key")
	}
	id, err := hexID(parts[1])
	if err != nil {
		return "", nil, nil, err
	}
	blob, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(blob) < 2 {
		return "", nil, nil, errors.New("malformed private key")
	}
	return parts[0], id, blob[1:], nil
}

func hexID(s string) ([]byte, error) {
	n, err := strconv.ParseUint(s, 16, 32)
	if err != nil || len(s) != 8 {
		return nil, errors.New("malformed key ID")
	}
	return binary.BigEndian.AppendUint32(nil, uint32(n)), nil
}

func openTyped() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 1<<24)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		parts := strings.Split(in.Text(), "\t")
		msg, _ := base64.StdEncoding.DecodeString(parts[0])
		var verifiers []note.Verifier
		failed := false
		if len(parts) > 1 && parts[1] != "" {
			for _, vkey := range strings.Split(parts[1], ",") {
				v, err := tdnote.NewVerifier(vkey)
				if err != nil {
					fmt.Fprintf(out, "err\tother\t%s\n", b64([]byte(err.Error())))
					failed = true
					break
				}
				verifiers = append(verifiers, v)
			}
		}
		if failed {
			continue
		}
		n, err := note.Open(msg, note.VerifierList(verifiers...))
		if err != nil {
			fmt.Fprintf(out, "err\t%s\t%s\n", openErrKind(err), b64([]byte(err.Error())))
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
}

// sthVerify checks an RFC 6962 note signature against the log key in a
// vkey, without going through transparency-dev — which only handles
// ECDSA. This is an independent reading of static-ct-api's framing and
// RFC 6962's TreeHeadSignature, so it judges the RSA path and
// double-checks the ECDSA one.
//
//	stdin:  vkey \t note_b64
//	stdout: ok \t timestamp  |  err \t msg_b64
func sthVerify() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 1<<24)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		parts := strings.Split(in.Text(), "\t")
		note, _ := base64.StdEncoding.DecodeString(parts[1])
		timestamp, err := verifySTHNote(parts[0], string(note))
		if err != nil {
			fmt.Fprintf(out, "err\t%s\n", b64([]byte(err.Error())))
			continue
		}
		fmt.Fprintf(out, "ok\t%d\n", timestamp)
	}
	if err := in.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "scan: %v\n", err)
		os.Exit(3)
	}
}

func verifySTHNote(vkey, note string) (uint64, error) {
	name, id, pub, err := parseSTHVkey(vkey)
	if err != nil {
		return 0, err
	}
	body, sigID, err := noteSignatureBody(note, name)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(sigID, id) {
		return 0, errors.New("key ID does not match the vkey")
	}
	if len(body) < timestampSize+4 {
		return 0, errors.New("signature body too short")
	}
	timestamp := binary.BigEndian.Uint64(body)
	rest := body[timestampSize:]
	hAlg, sAlg := rest[0], rest[1]
	rest = rest[2:]
	sigLen := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if len(rest) != sigLen {
		return 0, errors.New("digitally-signed length does not match")
	}
	if hAlg != 0x04 {
		return 0, errors.New("hash algorithm is not sha256")
	}

	text := note[:strings.Index(note, "\n\n")+1]
	sth, err := treeHeadSignatureBytes(name, timestamp, text)
	if err != nil {
		return 0, err
	}
	digest := sha256.Sum256(sth)

	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if sAlg != 0x03 {
			return 0, errors.New("signature algorithm is not ecdsa for an ECDSA key")
		}
		if key.Curve != elliptic.P256() {
			return 0, errors.New("RFC 6962 ECDSA keys must be on P-256")
		}
		if !ecdsa.VerifyASN1(key, digest[:], rest) {
			return 0, errors.New("ECDSA signature did not verify")
		}
	case *rsa.PublicKey:
		if sAlg != 0x01 {
			return 0, errors.New("signature algorithm is not rsa for an RSA key")
		}
		if key.N.BitLen() < 2048 {
			return 0, errors.New("RFC 6962 RSA keys must be at least 2048 bits")
		}
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], rest); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("unsupported log key type %T", pub)
	}
	return timestamp, nil
}

func parseSTHVkey(vkey string) (string, []byte, any, error) {
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		return "", nil, nil, errors.New("malformed vkey")
	}
	id, err := hexID(parts[1])
	if err != nil {
		return "", nil, nil, err
	}
	blob, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(blob) < 2 || blob[0] != algRFC6962 {
		return "", nil, nil, errors.New("malformed vkey key material")
	}
	pub, err := x509.ParsePKIXPublicKey(blob[1:])
	if err != nil {
		return "", nil, nil, err
	}
	// static-ct-api: the key ID hashes the name and the RFC 6962 LogID.
	if want := keyID(algRFC6962, parts[0], blob[1:]); want != parts[1] {
		return "", nil, nil, fmt.Errorf("key ID %s should be %s", parts[1], want)
	}
	return parts[0], id, pub, nil
}

// treeHeadSignatureBytes rebuilds the RFC 6962 Section 3.5 structure the
// signature covers, from the checkpoint in the note text.
func treeHeadSignatureBytes(name string, timestamp uint64, text string) ([]byte, error) {
	lines := strings.Split(text, "\n")
	if len(lines) != 4 || lines[3] != "" {
		return nil, errors.New("not a three-line checkpoint")
	}
	if lines[0] != name {
		return nil, errors.New("origin does not match the key name")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return nil, err
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(root) != sha256.Size {
		return nil, errors.New("root hash is not 32 bytes")
	}
	sth := []byte{0x00, 0x01}
	sth = binary.BigEndian.AppendUint64(sth, timestamp)
	sth = binary.BigEndian.AppendUint64(sth, size)
	return append(sth, root...), nil
}

// noteSignatureBody returns the bytes after the key ID on the signature
// line naming `name`, and that line's key ID.
func noteSignatureBody(note, name string) ([]byte, []byte, error) {
	split := strings.Index(note, "\n\n")
	if split < 0 {
		return nil, nil, errors.New("note has no blank line")
	}
	for _, line := range strings.Split(note[split+2:], "\n") {
		if !strings.HasPrefix(line, "— "+name+" ") {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "— "+name+" "))
		if err != nil || len(blob) < keyHashSize {
			return nil, nil, errors.New("malformed signature line")
		}
		return blob[keyHashSize:], blob[:keyHashSize], nil
	}
	return nil, nil, errors.New("no signature line for this key")
}

// subtreeSign and subtreeVerify drive the ML-DSA-44 subtree cosignatures
// of c2sp.org/tlog-cosignature, which have no note representation.
//
//	stdin:  skey \t origin \t start \t end \t hash_b64 \t timestamp
//	stdout: ok \t sig_b64  |  err \t msg_b64
func subtreeSign() {
	eachLine(func(parts []string) (string, error) {
		signer, err := tdnote.NewMLDSASigner(parts[0])
		if err != nil {
			return "", err
		}
		origin, start, end, hash, timestamp, err := subtreeArgs(parts[1:])
		if err != nil {
			return "", err
		}
		sig, err := signer.SignSubtree(timestamp, origin, start, end, hash)
		if err != nil {
			return "", err
		}
		return b64(sig), nil
	})
}

// stdin:  vkey \t origin \t start \t end \t hash_b64 \t timestamp \t sig_b64
// stdout: ok \t   |  err \t msg_b64
func subtreeVerify() {
	eachLine(func(parts []string) (string, error) {
		verifier, err := tdnote.NewMLDSAVerifier(parts[0])
		if err != nil {
			return "", err
		}
		origin, start, end, hash, timestamp, err := subtreeArgs(parts[1:])
		if err != nil {
			return "", err
		}
		sig, err := base64.StdEncoding.DecodeString(parts[6])
		if err != nil {
			return "", err
		}
		if !verifier.VerifySubtree(timestamp, origin, start, end, hash, sig) {
			return "", errors.New("subtree cosignature did not verify")
		}
		return "", nil
	})
}

func subtreeArgs(parts []string) (string, uint64, uint64, []byte, uint64, error) {
	start, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return "", 0, 0, nil, 0, err
	}
	end, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return "", 0, 0, nil, 0, err
	}
	hash, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return "", 0, 0, nil, 0, err
	}
	timestamp, err := strconv.ParseUint(parts[4], 10, 64)
	if err != nil {
		return "", 0, 0, nil, 0, err
	}
	return parts[0], start, end, hash, timestamp, nil
}

// eachLine runs f over tab-separated stdin lines, writing ok/err rows.
func eachLine(f func([]string) (string, error)) {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 1<<24)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		result, err := f(strings.Split(in.Text(), "\t"))
		if err != nil {
			fmt.Fprintf(out, "err\t%s\n", b64([]byte(err.Error())))
			continue
		}
		fmt.Fprintf(out, "ok\t%s\n", result)
	}
	if err := in.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "scan: %v\n", err)
		os.Exit(3)
	}
}

func openErrKind(err error) string {
	var unverified *note.UnverifiedNoteError
	var invalid *note.InvalidSignatureError
	switch {
	case errors.As(err, &unverified):
		return "unverified"
	case errors.As(err, &invalid):
		return "invalid"
	case strings.Contains(err.Error(), "malformed"):
		return "malformed"
	default:
		return "other"
	}
}
