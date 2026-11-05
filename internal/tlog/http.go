package tlog

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/ao3575911/atomhandle/internal/api"
	"github.com/ao3575911/atomhandle/internal/codec"
	"github.com/ao3575911/atomhandle/internal/merkle"
)

const maxBody = 64 << 10

// Handler serves the v1 log API. dev logs each request to the standard logger.
func (l *Log) Handler(dev bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+api.PathEntries, l.handleSubmit)
	mux.HandleFunc("GET "+api.PathEntries+"/{index}", l.handleEntry)
	mux.HandleFunc("GET "+api.PathInclusion, l.handleInclusion)
	mux.HandleFunc("GET "+api.PathConsistency, l.handleConsistency)
	mux.HandleFunc("GET "+api.PathCheckpoint, l.handleCheckpoint)
	if !dev {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.RequestURI())
		mux.ServeHTTP(w, r)
	})
}

func (l *Log) handleSubmit(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "body too large or unreadable")
		return
	}
	index, size, leaf, proof, cp, err := l.Submit(body, time.Now().UTC())
	if err != nil {
		writeStatus(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.SubmitResponse{
		Index:          index,
		TreeSize:       size,
		LeafHash:       codec.Encode(leaf),
		InclusionProof: merkle.EncodeHashes(proof),
		Checkpoint:     cp.Note,
		LogKey:         l.LogKey(),
	})
}

func (l *Log) handleEntry(w http.ResponseWriter, r *http.Request) {
	index, err := parseUint(r.PathValue("index"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad index")
		return
	}
	raw, leaf, err := l.Entry(index)
	if err != nil {
		writeStatus(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.EntryResponse{
		Index:    index,
		Document: append([]byte(nil), raw...),
		LeafHash: codec.Encode(leaf),
	})
}

func (l *Log) handleInclusion(w http.ResponseWriter, r *http.Request) {
	index, err1 := parseUint(r.URL.Query().Get("index"))
	size, err2 := parseUint(r.URL.Query().Get("size"))
	if err1 != nil || err2 != nil || r.URL.Query().Get("index") == "" || r.URL.Query().Get("size") == "" {
		writeErr(w, http.StatusBadRequest, "index and size are required")
		return
	}
	leaf, proof, err := l.InclusionProof(index, size)
	if err != nil {
		writeStatus(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.InclusionResponse{
		Index:    index,
		Size:     size,
		LeafHash: codec.Encode(leaf),
		Hashes:   merkle.EncodeHashes(proof),
	})
}

func (l *Log) handleConsistency(w http.ResponseWriter, r *http.Request) {
	first, err1 := parseUint(r.URL.Query().Get("first"))
	second, err2 := parseUint(r.URL.Query().Get("second"))
	if err1 != nil || err2 != nil || r.URL.Query().Get("first") == "" || r.URL.Query().Get("second") == "" {
		writeErr(w, http.StatusBadRequest, "first and second are required")
		return
	}
	proof, err := l.ConsistencyProof(first, second)
	if err != nil {
		writeStatus(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.ConsistencyResponse{
		First:  first,
		Second: second,
		Hashes: merkle.EncodeHashes(proof),
	})
}

func (l *Log) handleCheckpoint(w http.ResponseWriter, r *http.Request) {
	cp, err := l.Head()
	if err != nil {
		log.Printf("checkpoint: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, api.CheckpointResponse{
		Origin:     cp.Origin,
		Size:       cp.Size,
		RootHash:   codec.Encode(cp.Root),
		Checkpoint: cp.Note,
		LogKey:     l.LogKey(),
	})
}

func writeStatus(w http.ResponseWriter, err error) {
	var se *StatusError
	if errors.As(err, &se) {
		writeErr(w, se.Code, se.Msg)
		return
	}
	log.Printf("log: %v", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, api.ErrorResponse{Error: msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func parseUint(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != s {
		return 0, errors.New("bad integer")
	}
	return n, nil
}
