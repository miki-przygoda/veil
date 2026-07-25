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
