// Package handlers wires HTTP requests to the storage + detector layers.
// Handlers stay thin on purpose: parse inputs, call services, encode outputs.
package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/braidman/tenexai-assessment/backend/internal/ai"
	"github.com/braidman/tenexai-assessment/backend/internal/auth"
	"github.com/braidman/tenexai-assessment/backend/internal/detector"
	"github.com/braidman/tenexai-assessment/backend/internal/models"
	"github.com/braidman/tenexai-assessment/backend/internal/parser"
	"github.com/braidman/tenexai-assessment/backend/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const maxUploadBytes = 50 << 20 // 50MB — generous for log files; defensive cap

// Handler bundles the dependencies handlers need. Wired once at startup.
// AI is optional — nil means the LLM feature is disabled and the relevant
// endpoints return 503.
type Handler struct {
	Store storage.Store
	Auth  *auth.Manager
	Log   *slog.Logger
	AI    ai.Client
}

func New(s storage.Store, a *auth.Manager, aiClient ai.Client, log *slog.Logger) *Handler {
	return &Handler{Store: s, Auth: a, AI: aiClient, Log: log}
}

// --- Auth ---

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type loginResp struct {
	Token    string `json:"token"`
	Username string `json:"username"`
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	u, err := h.Store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		// Same response for "no such user" and "bad password" to avoid
		// username enumeration.
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err := auth.Verify(u.PasswordHash, req.Password); err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	tok, err := h.Auth.Issue(u.ID, u.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "issue token")
		return
	}
	writeJSON(w, http.StatusOK, loginResp{Token: tok, Username: u.Username})
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.FromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": c.Username})
}

// --- Uploads ---

type uploadResp struct {
	UploadID     uuid.UUID `json:"upload_id"`
	Filename     string    `json:"filename"`
	TotalRows    int       `json:"total_rows"`
	ParsedRows   int       `json:"parsed_rows"`
	SkippedRows  int       `json:"skipped_rows"`
	AnomalyCount int       `json:"anomaly_count"`
}

func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.FromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid multipart form (max 50MB)")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing 'file' field")
		return
	}
	defer file.Close()

	uploadID := uuid.New()
	res, err := parser.Parse(file, uploadID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("parse failed: %v", err))
		return
	}
	if res.ParsedRows == 0 {
		writeErr(w, http.StatusBadRequest, "no rows parsed — check CSV format")
		return
	}

	if err := h.Store.CreateUpload(r.Context(), &models.Upload{
		ID:         uploadID,
		UserID:     c.UserID,
		Filename:   header.Filename,
		TotalRows:  res.TotalRows,
		ParsedRows: res.ParsedRows,
		UploadedAt: time.Now().UTC(),
	}); err != nil {
		h.Log.Error("create upload", "err", err)
		writeErr(w, http.StatusInternalServerError, "create upload")
		return
	}

	entryIDs, err := h.Store.BulkInsertEntries(r.Context(), res.Entries)
	if err != nil {
		h.Log.Error("bulk insert entries", "err", err)
		writeErr(w, http.StatusInternalServerError, "store entries")
		return
	}

	anomalies := detector.Detect(uploadID, res.Entries, entryIDs)
	if err := h.Store.BulkInsertAnomalies(r.Context(), anomalies); err != nil {
		h.Log.Error("bulk insert anomalies", "err", err)
		writeErr(w, http.StatusInternalServerError, "store anomalies")
		return
	}

	writeJSON(w, http.StatusOK, uploadResp{
		UploadID:     uploadID,
		Filename:     header.Filename,
		TotalRows:    res.TotalRows,
		ParsedRows:   res.ParsedRows,
		SkippedRows:  res.SkippedRows,
		AnomalyCount: len(anomalies),
	})
}

func (h *Handler) ListUploads(w http.ResponseWriter, r *http.Request) {
	c := mustClaims(r)
	ups, err := h.Store.ListUploads(r.Context(), c.UserID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list uploads")
		return
	}
	writeJSON(w, http.StatusOK, ups)
}

func (h *Handler) GetUpload(w http.ResponseWriter, r *http.Request) {
	c := mustClaims(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	u, err := h.Store.GetUpload(r.Context(), id, c.UserID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "get upload")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *Handler) ListEntries(w http.ResponseWriter, r *http.Request) {
	c := mustClaims(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	// Verify ownership before disclosing anything.
	if _, err := h.Store.GetUpload(r.Context(), id, c.UserID); err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	anomalousOnly := strings.EqualFold(r.URL.Query().Get("anomalous"), "true")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	entries, total, err := h.Store.ListEntries(r.Context(), id, anomalousOnly, limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list entries")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

func (h *Handler) ListAnomalies(w http.ResponseWriter, r *http.Request) {
	c := mustClaims(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if _, err := h.Store.GetUpload(r.Context(), id, c.UserID); err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	out, err := h.Store.ListAnomalies(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list anomalies")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) Summary(w http.ResponseWriter, r *http.Request) {
	c := mustClaims(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if _, err := h.Store.GetUpload(r.Context(), id, c.UserID); err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	s, err := h.Store.Summary(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "summary")
		return
	}
	writeJSON(w, http.StatusOK, s)
}

// --- AI: SOC briefing ---

type briefingResp struct {
	Markdown    string    `json:"markdown"`
	GeneratedAt time.Time `json:"generated_at"`
	Cached      bool      `json:"cached"`
}

// GetBriefing returns the cached briefing or 404 if one hasn't been generated.
// Separate from PostBriefing so the dashboard can poll on load without
// triggering a fresh LLM call every render.
func (h *Handler) GetBriefing(w http.ResponseWriter, r *http.Request) {
	c := mustClaims(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	cached, err := h.Store.GetBriefing(r.Context(), id, c.UserID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "get briefing")
		return
	}
	if cached.Markdown == "" {
		writeErr(w, http.StatusNotFound, "no briefing yet")
		return
	}
	writeJSON(w, http.StatusOK, briefingResp{
		Markdown:    cached.Markdown,
		GeneratedAt: cached.GeneratedAt,
		Cached:      true,
	})
}

// PostBriefing calls the LLM (if configured) and caches the result.
// Returns the cached value if one exists unless ?regenerate=true is set.
func (h *Handler) PostBriefing(w http.ResponseWriter, r *http.Request) {
	if h.AI == nil {
		writeErr(w, http.StatusServiceUnavailable, "AI not configured (set ANTHROPIC_API_KEY)")
		return
	}
	c := mustClaims(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if _, err := h.Store.GetUpload(r.Context(), id, c.UserID); err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}

	regenerate := strings.EqualFold(r.URL.Query().Get("regenerate"), "true")
	if !regenerate {
		if cached, err := h.Store.GetBriefing(r.Context(), id, c.UserID); err == nil && cached.Markdown != "" {
			writeJSON(w, http.StatusOK, briefingResp{
				Markdown:    cached.Markdown,
				GeneratedAt: cached.GeneratedAt,
				Cached:      true,
			})
			return
		}
	}

	summary, err := h.Store.Summary(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "summary")
		return
	}
	anomalies, err := h.Store.ListAnomalies(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list anomalies")
		return
	}

	md, err := h.AI.GenerateBriefing(r.Context(), summary, anomalies)
	if err != nil {
		h.Log.Error("ai briefing", "err", err)
		writeErr(w, http.StatusBadGateway, fmt.Sprintf("AI call failed: %v", err))
		return
	}
	if err := h.Store.SaveBriefing(r.Context(), id, md); err != nil {
		h.Log.Error("save briefing", "err", err)
		// Still return the briefing even if caching failed — the user got the
		// content they asked for; the cache is a perf optimization, not a
		// correctness requirement.
	}
	writeJSON(w, http.StatusOK, briefingResp{
		Markdown:    md,
		GeneratedAt: time.Now().UTC(),
		Cached:      false,
	})
}

// --- AI: per-anomaly explanation ---

type explainResp struct {
	Markdown    string    `json:"markdown"`
	GeneratedAt time.Time `json:"generated_at"`
	Cached      bool      `json:"cached"`
}

func (h *Handler) PostAnomalyExplain(w http.ResponseWriter, r *http.Request) {
	if h.AI == nil {
		writeErr(w, http.StatusServiceUnavailable, "AI not configured (set ANTHROPIC_API_KEY)")
		return
	}
	c := mustClaims(r)
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}

	regenerate := strings.EqualFold(r.URL.Query().Get("regenerate"), "true")
	if !regenerate {
		if cached, err := h.Store.GetAnomalyExplanation(r.Context(), id, c.UserID); err == nil && cached.Markdown != "" {
			writeJSON(w, http.StatusOK, explainResp{
				Markdown:    cached.Markdown,
				GeneratedAt: cached.GeneratedAt,
				Cached:      true,
			})
			return
		}
	}

	anomaly, entry, err := h.Store.GetAnomalyWithEntry(r.Context(), id, c.UserID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "get anomaly")
		return
	}

	md, err := h.AI.ExplainAnomaly(r.Context(), *anomaly, entry)
	if err != nil {
		h.Log.Error("ai explain", "err", err)
		writeErr(w, http.StatusBadGateway, fmt.Sprintf("AI call failed: %v", err))
		return
	}
	if err := h.Store.SaveAnomalyExplanation(r.Context(), id, md); err != nil {
		h.Log.Error("save explanation", "err", err)
	}
	writeJSON(w, http.StatusOK, explainResp{
		Markdown:    md,
		GeneratedAt: time.Now().UTC(),
		Cached:      false,
	})
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// mustClaims asserts the JWT middleware ran and pulled claims into the context.
// Any handler that calls this is guarded by RequireJWT; a missing value means
// a routing bug, not a runtime case to handle. Panic surfaces the bug
// immediately (and chi's Recoverer converts it to a 500) instead of silently
// dereferencing nil.
func mustClaims(r *http.Request) *auth.Claims {
	c, ok := auth.FromContext(r.Context())
	if !ok {
		panic("handler invariant: RequireJWT must run before this handler")
	}
	return c
}
