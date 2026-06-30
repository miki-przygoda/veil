package sandbox

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDockerEngineHappyPaths(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/v1.43/images/present:1/json", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Id":"sha256:abc"}`))
	})
	mux.HandleFunc("/v1.43/images/missing:1/json", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"No such image"}`, http.StatusNotFound)
	})
	mux.HandleFunc("/v1.43/containers/create", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("name"); got != "veil-x" {
			t.Errorf("create ?name = %q, want veil-x", got)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"cid-1"}`))
	})
	mux.HandleFunc("/v1.43/containers/cid-1/start", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1.43/containers/gone", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
	})
	mux.HandleFunc("/v1.43/commit", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("container"); got != "cid-1" {
			t.Errorf("commit ?container = %q, want cid-1", got)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"img-2"}`))
	})
	mux.HandleFunc("/v1.43/images/img-ok", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"Untagged":"img-ok"}]`))
	})
	mux.HandleFunc("/v1.43/images/img-gone", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"No such image"}`, http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	eng := newEngineWithClient(srv.Client(), srv.URL)
	ctx := context.Background()

	if err := eng.ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if ok, err := eng.imageExists(ctx, "present:1"); err != nil || !ok {
		t.Fatalf("imageExists present: ok=%v err=%v", ok, err)
	}
	if ok, err := eng.imageExists(ctx, "missing:1"); err != nil || ok {
		t.Fatalf("imageExists missing: ok=%v err=%v", ok, err)
	}
	if id, err := eng.create(ctx, createSpec{name: "veil-x", Image: "present:1"}); err != nil || id != "cid-1" {
		t.Fatalf("create: id=%q err=%v", id, err)
	}
	if err := eng.start(ctx, "cid-1"); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := eng.remove(ctx, "gone", true); err != nil {
		t.Fatalf("remove must tolerate 404: %v", err)
	}
	if img, err := eng.commit(ctx, "cid-1", "veil-snap-x:latest"); err != nil || img != "img-2" {
		t.Fatalf("commit: img=%q err=%v", img, err)
	}
	if err := eng.removeImage(ctx, "img-ok"); err != nil {
		t.Fatalf("removeImage 200: %v", err)
	}
	if err := eng.removeImage(ctx, "img-gone"); err != nil {
		t.Fatalf("removeImage must tolerate 404: %v", err)
	}
}

func TestDockerEnginePingUnavailable(t *testing.T) {
	eng, err := newDockerEngine("unix:///nonexistent/veil-test.sock")
	if err != nil {
		t.Fatalf("newDockerEngine: %v", err)
	}
	if err := eng.ping(context.Background()); !errors.Is(err, ErrEngineUnavailable) {
		t.Fatalf("ping err = %v, want ErrEngineUnavailable", err)
	}
}
