package docker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
