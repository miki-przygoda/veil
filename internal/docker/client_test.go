package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDockerClientHappyPaths(t *testing.T) {
	mux := http.NewServeMux()
	vp := "/" + dockerAPIVersion // versioned-endpoint prefix, kept in sync with the client
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc(vp+"/images/present:1/json", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Id":"sha256:abc"}`))
	})
	mux.HandleFunc(vp+"/images/missing:1/json", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"No such image"}`, http.StatusNotFound)
	})
	mux.HandleFunc(vp+"/containers/create", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("name"); got != "veil-x" {
			t.Errorf("create ?name = %q, want veil-x", got)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"cid-1"}`))
	})
	mux.HandleFunc(vp+"/containers/cid-1/start", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc(vp+"/containers/gone", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
	})
	mux.HandleFunc(vp+"/commit", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("container"); got != "cid-1" {
			t.Errorf("commit ?container = %q, want cid-1", got)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"img-2"}`))
	})
	mux.HandleFunc(vp+"/images/img-ok", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"Untagged":"img-ok"}]`))
	})
	mux.HandleFunc(vp+"/images/img-gone", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"No such image"}`, http.StatusNotFound)
	})
	mux.HandleFunc(vp+"/networks/create", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["Name"] != "veil-net" || body["Internal"] != true {
			t.Errorf("network create body = %v, want Name=veil-net Internal=true", body)
		}
		opts, _ := body["Options"].(map[string]any)
		if opts["com.docker.network.bridge.name"] != "veil-br0" {
			t.Errorf("network create Options bridge name = %v, want veil-br0", opts)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"net-1"}`))
	})
	mux.HandleFunc(vp+"/networks/net-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Id":"net-1","Name":"veil-net","Internal":true,"Options":{"com.docker.network.bridge.name":"veil-br0"},"IPAM":{"Config":[{"Subnet":"172.20.0.0/16","Gateway":"172.20.0.1"}]}}`))
	})
	mux.HandleFunc(vp+"/networks/missing", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	cli := newClientWithHTTP(srv.Client(), srv.URL)
	ctx := context.Background()

	if err := cli.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if ok, err := cli.ImageExists(ctx, "present:1"); err != nil || !ok {
		t.Fatalf("ImageExists present: ok=%v err=%v", ok, err)
	}
	if ok, err := cli.ImageExists(ctx, "missing:1"); err != nil || ok {
		t.Fatalf("ImageExists missing: ok=%v err=%v", ok, err)
	}
	if id, err := cli.CreateContainer(ctx, CreateSpec{Name: "veil-x", Image: "present:1"}); err != nil || id != "cid-1" {
		t.Fatalf("CreateContainer: id=%q err=%v", id, err)
	}
	if err := cli.StartContainer(ctx, "cid-1"); err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
	if err := cli.RemoveContainer(ctx, "gone", true); err != nil {
		t.Fatalf("RemoveContainer must tolerate 404: %v", err)
	}
	if img, err := cli.Commit(ctx, "cid-1", "veil-snap-x:latest"); err != nil || img != "img-2" {
		t.Fatalf("Commit: img=%q err=%v", img, err)
	}
	if err := cli.RemoveImage(ctx, "img-ok"); err != nil {
		t.Fatalf("RemoveImage 200: %v", err)
	}
	if err := cli.RemoveImage(ctx, "img-gone"); err != nil {
		t.Fatalf("RemoveImage must tolerate 404: %v", err)
	}
	id, err := cli.CreateNetwork(ctx, NetworkSpec{Name: "veil-net", Internal: true, Labels: map[string]string{"com.veil.managed": "true"}, BridgeName: "veil-br0"})
	if err != nil || id != "net-1" {
		t.Fatalf("CreateNetwork: id=%q err=%v", id, err)
	}
	n, err := cli.InspectNetwork(ctx, "net-1")
	if err != nil || n.Bridge != "veil-br0" || !n.Internal {
		t.Fatalf("InspectNetwork: %+v err=%v", n, err)
	}
	if n.Subnet != "172.20.0.0/16" || n.Gateway != "172.20.0.1" {
		t.Errorf("IPAM = %q / %q, want 172.20.0.0/16 / 172.20.0.1", n.Subnet, n.Gateway)
	}
	if err := cli.RemoveNetwork(ctx, "net-1"); err != nil {
		t.Fatalf("RemoveNetwork: %v", err)
	}
	if err := cli.RemoveNetwork(ctx, "missing"); err != nil {
		t.Fatalf("RemoveNetwork must tolerate 404: %v", err)
	}
}

func TestDockerClientPingUnavailable(t *testing.T) {
	cli, err := New("unix:///nonexistent/veil-test.sock")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := cli.Ping(context.Background()); !errors.Is(err, ErrEngineUnavailable) {
		t.Fatalf("Ping err = %v, want ErrEngineUnavailable", err)
	}
}

func TestCreateSpecStaticIPAndCapAdd(t *testing.T) {
	spec := CreateSpec{
		Image:      "img",
		HostConfig: HostConfig{CapAdd: []string{"NET_BIND_SERVICE"}},
		NetworkingConfig: &NetworkingConfig{EndpointsConfig: map[string]EndpointConfig{
			"veil-net": {IPAMConfig: &EndpointIPAM{IPv4Address: "172.20.0.10"}},
		}},
	}
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"CapAdd":["NET_BIND_SERVICE"]`, `"EndpointsConfig"`, `"IPv4Address":"172.20.0.10"`} {
		if !strings.Contains(s, want) {
			t.Errorf("marshalled spec missing %s:\n%s", want, s)
		}
	}
	// A spec that sets neither must omit both (omitempty).
	def, _ := json.Marshal(CreateSpec{Image: "x"})
	if strings.Contains(string(def), "NetworkingConfig") || strings.Contains(string(def), "CapAdd") {
		t.Errorf("empty spec must omit NetworkingConfig/CapAdd: %s", def)
	}
}

func TestExecEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	vp := "/" + dockerAPIVersion
	mux.HandleFunc(vp+"/containers/cid/exec", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["Tty"] != true || body["AttachStdout"] != true || body["AttachStderr"] != true {
			t.Errorf("exec create body = %v, want Tty+AttachStdout+AttachStderr true", body)
		}
		cmd, _ := body["Cmd"].([]any)
		if len(cmd) != 3 || cmd[0] != "/bin/sh" || cmd[1] != "-c" {
			t.Errorf("exec create Cmd = %v, want [/bin/sh -c ...]", body["Cmd"])
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"exec-9"}`))
	})
	mux.HandleFunc(vp+"/exec/exec-9/start", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["Detach"] != false || body["Tty"] != true {
			t.Errorf("exec start body = %v, want Detach=false Tty=true", body)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("total 0\nhello\n"))
	})
	mux.HandleFunc(vp+"/exec/exec-9/json", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ExitCode":42,"Running":false}`))
	})
	// A flooding exec must be bounded to execOutputCap.
	mux.HandleFunc(vp+"/exec/flood/start", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("A"), execOutputCap+4096))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	cli := newClientWithHTTP(srv.Client(), srv.URL)
	ctx := context.Background()

	execID, err := cli.ExecCreate(ctx, "cid", []string{"/bin/sh", "-c", "ls"})
	if err != nil || execID != "exec-9" {
		t.Fatalf("ExecCreate: id=%q err=%v", execID, err)
	}
	out, err := cli.ExecStart(ctx, execID)
	if err != nil || string(out) != "total 0\nhello\n" {
		t.Fatalf("ExecStart: out=%q err=%v", out, err)
	}
	code, err := cli.ExecInspect(ctx, execID)
	if err != nil || code != 42 {
		t.Fatalf("ExecInspect: code=%d err=%v", code, err)
	}
	flood, err := cli.ExecStart(ctx, "flood")
	if err != nil || len(flood) != execOutputCap {
		t.Fatalf("ExecStart cap: got %d bytes err=%v, want %d", len(flood), err, execOutputCap)
	}
}

func TestExecAttach(t *testing.T) {
	vp := "/" + dockerAPIVersion
	mux := http.NewServeMux()
	mux.HandleFunc(vp+"/containers/cid/exec", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["AttachStdin"] != true || body["Tty"] != false {
			t.Errorf("attach create body = %v, want AttachStdin=true Tty=false", body)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"exec-9"}`))
	})
	mux.HandleFunc(vp+"/exec/exec-9/start", func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("ResponseWriter is not a Hijacker")
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
		payload := "hi\n"
		buf.Write([]byte{1, 0, 0, 0, 0, 0, 0, byte(len(payload))}) // stdout frame header
		buf.WriteString(payload)
		_ = buf.Flush()
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newClientWithHTTP(srv.Client(), srv.URL)
	conn, err := c.ExecAttach(context.Background(), "cid", []string{"/bin/sh"})
	if err != nil {
		t.Fatalf("ExecAttach: %v", err)
	}
	defer conn.Close()

	stream, payload, err := DemuxFrame(conn)
	if err != nil {
		t.Fatalf("DemuxFrame: %v", err)
	}
	if stream != 1 || string(payload) != "hi\n" {
		t.Errorf("frame = stream %d %q, want 1 \"hi\\n\"", stream, payload)
	}
}

func TestDemuxFrameRejectsOversizeFrame(t *testing.T) {
	// header claiming ~4 GiB payload, no body
	hdr := []byte{1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}
	if _, _, err := DemuxFrame(bytes.NewReader(hdr)); err == nil {
		t.Error("DemuxFrame must reject a frame whose declared length exceeds maxFrameSize")
	}
}

// Past the cap, ExecStart must keep draining the stream to EOF (discarding the
// excess) rather than closing it: closing early leaves the TTY process blocked
// writing inside the box, holding a PID against PidsLimit.
func TestExecStartDrainsPastCap(t *testing.T) {
	vp := "/" + dockerAPIVersion
	const total = 4 << 20 // far more than any socket buffer can absorb
	wrote := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(vp+"/exec/flood/start", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := bytes.Repeat([]byte("A"), 32<<10)
		var err error
		for n := 0; n < total && err == nil; n += len(chunk) {
			_, err = w.Write(chunk)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		wrote <- err
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	cli := newClientWithHTTP(srv.Client(), srv.URL)

	out, err := cli.ExecStart(context.Background(), "flood")
	if err != nil || len(out) != execOutputCap {
		t.Fatalf("ExecStart: got %d bytes err=%v, want %d", len(out), err, execOutputCap)
	}
	select {
	case werr := <-wrote:
		if werr != nil {
			t.Errorf("server write failed (stream closed before EOF, not drained): %v", werr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never finished writing: ExecStart did not drain the stream")
	}
}

// ExecInspect must not report a still-running exec, or one whose ExitCode is
// null/absent, as a clean exit 0.
func TestExecInspectUnfinished(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantCode int
		wantErr  bool
	}{
		{"finished zero", `{"ExitCode":0,"Running":false}`, 0, false},
		{"finished nonzero", `{"ExitCode":7,"Running":false}`, 7, false},
		{"still running", `{"ExitCode":0,"Running":true}`, -1, true},
		{"null exit code", `{"ExitCode":null,"Running":false}`, -1, true},
		{"absent exit code", `{"Running":false}`, -1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vp := "/" + dockerAPIVersion
			mux := http.NewServeMux()
			mux.HandleFunc(vp+"/exec/e/json", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()
			cli := newClientWithHTTP(srv.Client(), srv.URL)

			code, err := cli.ExecInspect(context.Background(), "e")
			if code != tc.wantCode {
				t.Errorf("code = %d, want %d", code, tc.wantCode)
			}
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrExecUnfinished) {
				t.Errorf("err = %v, want ErrExecUnfinished", err)
			}
		})
	}
}

// A daemon that accepts the exec start but never answers the upgrade must not
// wedge ExecAttach: a ctx deadline, a ctx cancel, or (with neither) the default
// handshake timeout each unblock it.
func TestExecAttachHandshakeStall(t *testing.T) {
	cases := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
	}{
		{"ctx deadline", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 200*time.Millisecond)
		}},
		{"ctx cancel", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(200*time.Millisecond, cancel)
			return ctx, cancel
		}},
		{"default timeout", func() (context.Context, context.CancelFunc) {
			return context.Background(), func() {}
		}},
	}
	old := attachHandshakeTimeout
	attachHandshakeTimeout = 300 * time.Millisecond
	defer func() { attachHandshakeTimeout = old }()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vp := "/" + dockerAPIVersion
			mux := http.NewServeMux()
			mux.HandleFunc(vp+"/containers/cid/exec", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"Id":"exec-s"}`))
			})
			mux.HandleFunc(vp+"/exec/exec-s/start", func(w http.ResponseWriter, _ *http.Request) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("hijack: %v", err)
					return
				}
				defer conn.Close()
				_, _ = conn.Read(make([]byte, 1)) // stall until the client hangs up
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()
			cli := newClientWithHTTP(srv.Client(), srv.URL)

			ctx, cancel := tc.ctx()
			defer cancel()
			done := make(chan error, 1)
			go func() {
				conn, err := cli.ExecAttach(ctx, "cid", []string{"/bin/sh"})
				if conn != nil {
					conn.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("ExecAttach against a stalled daemon must error")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("ExecAttach wedged on a stalled handshake")
			}
		})
	}
}

// The handshake deadline must be cleared on success: the hijacked stream is
// long-lived and must keep working after the ctx deadline has passed.
func TestExecAttachClearsDeadline(t *testing.T) {
	vp := "/" + dockerAPIVersion
	mux := http.NewServeMux()
	mux.HandleFunc(vp+"/containers/cid/exec", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"exec-d"}`))
	})
	mux.HandleFunc(vp+"/exec/exec-d/start", func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
		_ = buf.Flush()
		time.Sleep(400 * time.Millisecond) // well past the client's ctx deadline
		payload := "late\n"
		buf.Write([]byte{1, 0, 0, 0, 0, 0, 0, byte(len(payload))})
		buf.WriteString(payload)
		_ = buf.Flush()
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	cli := newClientWithHTTP(srv.Client(), srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	conn, err := cli.ExecAttach(ctx, "cid", []string{"/bin/sh"})
	if err != nil {
		t.Fatalf("ExecAttach: %v", err)
	}
	defer conn.Close()
	_, payload, err := DemuxFrame(conn)
	if err != nil || string(payload) != "late\n" {
		t.Fatalf("read after ctx deadline: payload=%q err=%v (handshake deadline not cleared?)", payload, err)
	}
}

// TestEngineVersion: GET /version is queried UNVERSIONED (an engine older than
// the pinned API would reject a /v1.44/ prefix — exactly the engines the caller
// needs to detect), returns the engine's Version string, and surfaces non-200s.
func TestEngineVersion(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		want    string
		wantErr bool
	}{
		{"ok", http.StatusOK, `{"Version":"29.1.3","ApiVersion":"1.52"}`, "29.1.3", false},
		{"old engine", http.StatusOK, `{"Version":"24.0.7","ApiVersion":"1.43"}`, "24.0.7", false},
		{"server error", http.StatusInternalServerError, `{"message":"boom"}`, "", true},
		{"bad json", http.StatusOK, `not json`, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("method = %s, want GET", r.Method)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()
			cli := newClientWithHTTP(srv.Client(), srv.URL)
			got, err := cli.EngineVersion(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("version = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEngineVersionUnavailable(t *testing.T) {
	cli, err := New("unix:///nonexistent/veil-test.sock")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := cli.EngineVersion(context.Background()); !errors.Is(err, ErrEngineUnavailable) {
		t.Fatalf("EngineVersion err = %v, want ErrEngineUnavailable", err)
	}
}
