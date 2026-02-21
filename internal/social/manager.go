package social

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"ClawdCity-Apps/internal/localrpcclient"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
)

const (
	AppID                = "social"
	topicPresence        = "app.social.v1.global.presence"
	topicGlobalFeed      = "app.social.v1.global.feed"
	defaultInviteTTL     = 24 * time.Hour
	defaultPresenceEvery = 30 * time.Second
)

type Settings struct {
	Discoverable          bool `json:"discoverable"`
	AllowStrangerRequests bool `json:"allow_stranger_requests"`
	AllowGlobalFeed       bool `json:"allow_global_feed"`
}

type Profile struct {
	UserID         string    `json:"user_id"`
	Username       string    `json:"username"`
	Bio            string    `json:"bio"`
	AvatarData     string    `json:"avatar_data,omitempty"`
	SignPublicKey  string    `json:"sign_public_key"`
	BoxPublicKey   string    `json:"box_public_key"`
	Settings       Settings  `json:"settings"`
	InitializedAt  time.Time `json:"initialized_at"`
	LastUpdatedAt  time.Time `json:"last_updated_at"`
	PresenceSentAt time.Time `json:"presence_sent_at,omitempty"`
}

type KnownUser struct {
	UserID        string    `json:"user_id"`
	Username      string    `json:"username"`
	Bio           string    `json:"bio"`
	AvatarData    string    `json:"avatar_data,omitempty"`
	SignPublicKey string    `json:"sign_public_key"`
	BoxPublicKey  string    `json:"box_public_key"`
	LastSeenAt    time.Time `json:"last_seen_at"`
}

type FriendRequest struct {
	RequestID  string    `json:"request_id"`
	FromUserID string    `json:"from_user_id"`
	ToUserID   string    `json:"to_user_id"`
	FromName   string    `json:"from_name,omitempty"`
	Message    string    `json:"message,omitempty"`
	Method     string    `json:"method,omitempty"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Friend struct {
	UserID    string    `json:"user_id"`
	Alias     string    `json:"alias,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type DirectMessage struct {
	MessageID  string    `json:"message_id"`
	FromUserID string    `json:"from_user_id"`
	ToUserID   string    `json:"to_user_id"`
	Body       string    `json:"body"`
	CreatedAt  time.Time `json:"created_at"`
}

type Broadcast struct {
	MessageID string    `json:"message_id"`
	FromUser  string    `json:"from_user"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
}

type Identity struct {
	UserID        string
	SignPublicKey ed25519.PublicKey
	SignPrivate   ed25519.PrivateKey
	BoxPublicKey  [32]byte
	BoxPrivateKey [32]byte
}

type Config struct {
	DataDir       string
	RPCSocketPath string
	Passphrase    string
}

type Manager struct {
	mu sync.RWMutex

	cfg Config
	rpc *localrpcclient.Client

	profile         *Profile
	identity        *Identity
	knownUsers      map[string]KnownUser
	requests        map[string]FriendRequest
	friends         map[string]Friend
	dms             map[string][]DirectMessage
	broadcasts      []Broadcast
	usedInviteNonce map[string]time.Time
	cursors         map[string]int64
	seenMessageIDs  map[string]struct{}
	listeners       map[int]chan string
	nextListenerID  int

	subscriptionID string
	cancel         context.CancelFunc
}

func NewManager(cfg Config) (*Manager, error) {
	if cfg.DataDir == "" {
		cfg.DataDir = filepath.Join("data", "social")
	}
	m := &Manager{
		cfg:             cfg,
		rpc:             localrpcclient.New(cfg.RPCSocketPath),
		knownUsers:      make(map[string]KnownUser),
		requests:        make(map[string]FriendRequest),
		friends:         make(map[string]Friend),
		dms:             make(map[string][]DirectMessage),
		usedInviteNonce: make(map[string]time.Time),
		cursors:         make(map[string]int64),
		seenMessageIDs:  make(map[string]struct{}),
		listeners:       make(map[int]chan string),
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, err
	}
	_ = m.loadState()
	if cfg.Passphrase != "" {
		_ = m.unlock(cfg.Passphrase)
	}
	if m.profile != nil && m.identity != nil {
		m.startLoop()
	}
	return m, nil
}

func (m *Manager) Initialized() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.profile != nil && m.identity != nil
}

func (m *Manager) Unlock(passphrase string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.unlock(passphrase); err != nil {
		return err
	}
	if m.cancel == nil {
		m.startLoopLocked()
	}
	return nil
}

func (m *Manager) Init(username, bio, avatarData, passphrase string, settings Settings) (*Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.profile != nil {
		return nil, errors.New("already initialized")
	}
	if strings.TrimSpace(username) == "" {
		return nil, errors.New("username required")
	}
	if len(avatarData) > 350000 {
		return nil, errors.New("avatar too large")
	}
	if strings.TrimSpace(passphrase) == "" {
		return nil, errors.New("passphrase required")
	}

	id, err := generateIdentity()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	p := &Profile{
		UserID:        id.UserID,
		Username:      strings.TrimSpace(username),
		Bio:           strings.TrimSpace(bio),
		AvatarData:    avatarData,
		SignPublicKey: base64.RawStdEncoding.EncodeToString(id.SignPublicKey),
		BoxPublicKey:  base64.RawStdEncoding.EncodeToString(id.BoxPublicKey[:]),
		Settings:      normalizeSettings(settings),
		InitializedAt: now,
		LastUpdatedAt: now,
	}
	m.profile = p
	m.identity = id
	m.cfg.Passphrase = passphrase
	if err := m.saveIdentity(passphrase); err != nil {
		return nil, err
	}
	if err := m.saveStateLocked(); err != nil {
		return nil, err
	}
	m.startLoopLocked()
	go m.publishPresence()
	cp := *p
	return &cp, nil
}

func (m *Manager) UpdateProfile(username, bio, avatarData string, settings Settings) (*Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.profile == nil {
		return nil, errors.New("not initialized")
	}
	if strings.TrimSpace(username) != "" {
		m.profile.Username = strings.TrimSpace(username)
	}
	m.profile.Bio = strings.TrimSpace(bio)
	if avatarData != "" {
		if len(avatarData) > 350000 {
			return nil, errors.New("avatar too large")
		}
		m.profile.AvatarData = avatarData
	}
	m.profile.Settings = normalizeSettings(settings)
	m.profile.LastUpdatedAt = time.Now().UTC()
	if err := m.saveStateLocked(); err != nil {
		return nil, err
	}
	go m.publishPresence()
	cp := *m.profile
	return &cp, nil
}

func normalizeSettings(s Settings) Settings {
	return s
}

func (m *Manager) Snapshot() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	known := make([]KnownUser, 0, len(m.knownUsers))
	for _, u := range m.knownUsers {
		known = append(known, u)
	}
	sort.Slice(known, func(i, j int) bool { return known[i].LastSeenAt.After(known[j].LastSeenAt) })

	reqs := make([]FriendRequest, 0, len(m.requests))
	for _, r := range m.requests {
		reqs = append(reqs, r)
	}
	sort.Slice(reqs, func(i, j int) bool { return reqs[i].CreatedAt.After(reqs[j].CreatedAt) })

	friends := make([]Friend, 0, len(m.friends))
	for _, f := range m.friends {
		friends = append(friends, f)
	}
	sort.Slice(friends, func(i, j int) bool { return friends[i].CreatedAt.After(friends[j].CreatedAt) })

	bcasts := append([]Broadcast(nil), m.broadcasts...)
	if len(bcasts) > 60 {
		bcasts = bcasts[len(bcasts)-60:]
	}

	me := (*Profile)(nil)
	if m.profile != nil {
		cp := *m.profile
		me = &cp
	}

	return map[string]any{
		"initialized": m.profile != nil && m.identity != nil,
		"me":          me,
		"discovery":   known,
		"requests":    reqs,
		"friends":     friends,
		"broadcasts":  bcasts,
	}
}

func (m *Manager) SubscribeEvents() (<-chan string, func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextListenerID
	m.nextListenerID++
	ch := make(chan string, 64)
	m.listeners[id] = ch
	cancel := func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if c, ok := m.listeners[id]; ok {
			delete(m.listeners, id)
			close(c)
		}
	}
	return ch, cancel
}

func (m *Manager) Broadcast(text string) error {
	m.mu.RLock()
	profile := m.profile
	m.mu.RUnlock()
	if profile == nil {
		return errors.New("not initialized")
	}
	if !profile.Settings.AllowGlobalFeed {
		return errors.New("global feed disabled")
	}
	body := map[string]any{
		"message_id": fmt.Sprintf("b-%d", time.Now().UnixNano()),
		"from_user":  profile.UserID,
		"username":   profile.Username,
		"text":       strings.TrimSpace(text),
		"created_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	if strings.TrimSpace(text) == "" {
		return errors.New("text required")
	}
	return m.publishPlain(topicGlobalFeed, body)
}

func (m *Manager) SendFriendRequest(targetUserID, message, method string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.profile == nil || m.identity == nil {
		return errors.New("not initialized")
	}
	target, ok := m.knownUsers[targetUserID]
	if !ok {
		return errors.New("target user not found in discovery")
	}
	reqID := fmt.Sprintf("fr-%d", time.Now().UnixNano())
	req := FriendRequest{RequestID: reqID, FromUserID: m.profile.UserID, ToUserID: targetUserID, FromName: m.profile.Username, Message: message, Method: method, Status: "pending_out", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	m.requests[reqID] = req
	payload := map[string]any{
		"type":         "friend_request",
		"request_id":   reqID,
		"from_user_id": m.profile.UserID,
		"from_name":    m.profile.Username,
		"message":      message,
		"method":       method,
		"created_at":   req.CreatedAt.Format(time.RFC3339Nano),
	}
	if err := m.publishSecureLocked(inboxTopic(targetUserID), target.BoxPublicKey, payload); err != nil {
		return err
	}
	return m.saveStateLocked()
}

func (m *Manager) RespondFriendRequest(requestID string, accept bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, ok := m.requests[requestID]
	if !ok {
		return errors.New("request not found")
	}
	if m.profile == nil || m.identity == nil {
		return errors.New("not initialized")
	}
	if req.Status != "pending_in" {
		return errors.New("request already handled")
	}
	status := "rejected"
	if accept {
		status = "accepted"
		m.friends[req.FromUserID] = Friend{UserID: req.FromUserID, CreatedAt: time.Now().UTC()}
	}
	req.Status = status
	req.UpdatedAt = time.Now().UTC()
	m.requests[requestID] = req
	target, ok := m.knownUsers[req.FromUserID]
	if !ok {
		return errors.New("request sender not discovered")
	}
	payload := map[string]any{
		"type":         "friend_response",
		"request_id":   requestID,
		"status":       status,
		"from_user_id": m.profile.UserID,
		"created_at":   time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := m.publishSecureLocked(inboxTopic(req.FromUserID), target.BoxPublicKey, payload); err != nil {
		return err
	}
	return m.saveStateLocked()
}

func (m *Manager) SendDirectMessage(toUserID, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.friends[toUserID]; !ok {
		return errors.New("target is not a friend")
	}
	target, ok := m.knownUsers[toUserID]
	if !ok {
		return errors.New("target user not discovered")
	}
	if strings.TrimSpace(body) == "" {
		return errors.New("message body required")
	}
	msgID := fmt.Sprintf("dm-%d", time.Now().UnixNano())
	msg := DirectMessage{MessageID: msgID, FromUserID: m.profile.UserID, ToUserID: toUserID, Body: strings.TrimSpace(body), CreatedAt: time.Now().UTC()}
	m.dms[toUserID] = append(m.dms[toUserID], msg)
	payload := map[string]any{
		"type":         "dm_message",
		"message_id":   msgID,
		"from_user_id": m.profile.UserID,
		"body":         msg.Body,
		"created_at":   msg.CreatedAt.Format(time.RFC3339Nano),
	}
	if err := m.publishSecureLocked(inboxTopic(toUserID), target.BoxPublicKey, payload); err != nil {
		return err
	}
	return m.saveStateLocked()
}

func (m *Manager) Conversation(peerUserID string) []DirectMessage {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := append([]DirectMessage(nil), m.dms[peerUserID]...)
	if len(out) > 200 {
		out = out[len(out)-200:]
	}
	return out
}

func (m *Manager) CreateInviteLink() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.profile == nil || m.identity == nil {
		return "", errors.New("not initialized")
	}
	nonceRaw := make([]byte, 12)
	if _, err := rand.Read(nonceRaw); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(nonceRaw)
	payload := map[string]any{
		"v":          1,
		"user_id":    m.profile.UserID,
		"username":   m.profile.Username,
		"box_pub":    m.profile.BoxPublicKey,
		"sign_pub":   m.profile.SignPublicKey,
		"nonce":      nonce,
		"expires_at": time.Now().UTC().Add(defaultInviteTTL).Unix(),
	}
	body, _ := json.Marshal(payload)
	sig := ed25519.Sign(m.identity.SignPrivate, body)
	token := base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(sig)
	return token, nil
}

func (m *Manager) SendFriendRequestByInvite(token, message string) error {
	payload, err := parseInvite(token)
	if err != nil {
		return err
	}
	userID, _ := payload["user_id"].(string)
	boxPub, _ := payload["box_pub"].(string)
	nonce, _ := payload["nonce"].(string)
	if userID == "" || boxPub == "" {
		return errors.New("invalid invite payload")
	}
	m.mu.Lock()
	if m.profile == nil || m.identity == nil {
		m.mu.Unlock()
		return errors.New("not initialized")
	}
	if nonce != "" {
		if _, ok := m.usedInviteNonce[nonce]; ok {
			m.mu.Unlock()
			return errors.New("invite already used")
		}
		m.usedInviteNonce[nonce] = time.Now().UTC()
	}
	m.knownUsers[userID] = KnownUser{UserID: userID, Username: asString(payload["username"]), SignPublicKey: asString(payload["sign_pub"]), BoxPublicKey: boxPub, LastSeenAt: time.Now().UTC()}
	_ = m.saveStateLocked()
	m.mu.Unlock()
	return m.SendFriendRequest(userID, message, "invite")
}

func parseInvite(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	signPubB64, _ := payload["sign_pub"].(string)
	expiresF, _ := payload["expires_at"].(float64)
	if time.Now().UTC().Unix() > int64(expiresF) {
		return nil, errors.New("invite expired")
	}
	signPub, err := base64.RawStdEncoding.DecodeString(signPubB64)
	if err != nil || len(signPub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid invite sign key")
	}
	if !ed25519.Verify(ed25519.PublicKey(signPub), body, sig) {
		return nil, errors.New("invite signature invalid")
	}
	return payload, nil
}

func (m *Manager) publishPresence() {
	m.mu.RLock()
	profile := m.profile
	m.mu.RUnlock()
	if profile == nil || !profile.Settings.Discoverable {
		return
	}
	body := map[string]any{
		"user_id":         profile.UserID,
		"username":        profile.Username,
		"bio":             profile.Bio,
		"avatar_data":     profile.AvatarData,
		"sign_public_key": profile.SignPublicKey,
		"box_public_key":  profile.BoxPublicKey,
		"settings":        profile.Settings,
		"ts":              time.Now().UTC().Format(time.RFC3339Nano),
	}
	_ = m.publishPlain(topicPresence, body)
}

func (m *Manager) publishPlain(topic string, body map[string]any) error {
	wire := map[string]any{
		"version": 1,
		"kind":    "plain",
		"body":    body,
	}
	data, _ := json.Marshal(wire)
	rep, err := m.rpc.Publish(localrpcclient.PublishArgs{AppID: AppID, Topic: topic, Payload: data})
	if err != nil {
		return err
	}
	if rep.Error != "" {
		return errors.New(rep.Error)
	}
	return nil
}

func (m *Manager) publishSecureLocked(topic, recipientBoxPubB64 string, body map[string]any) error {
	if m.identity == nil || m.profile == nil {
		return errors.New("identity not ready")
	}
	peerPubRaw, err := base64.RawStdEncoding.DecodeString(recipientBoxPubB64)
	if err != nil || len(peerPubRaw) != 32 {
		return errors.New("invalid recipient key")
	}
	var peerPub [32]byte
	copy(peerPub[:], peerPubRaw)

	plain, _ := json.Marshal(body)
	cipherText, nonce, err := encryptForPeer(m.identity.BoxPrivateKey, peerPub, plain)
	if err != nil {
		return err
	}
	msgID := fmt.Sprintf("s-%d", time.Now().UnixNano())
	secure := map[string]any{
		"version":         1,
		"kind":            "secure",
		"msg_id":          msgID,
		"from_user_id":    m.profile.UserID,
		"sender_sign_pub": m.profile.SignPublicKey,
		"sender_box_pub":  m.profile.BoxPublicKey,
		"to_user_id":      userIDFromInboxTopic(topic),
		"nonce":           base64.RawStdEncoding.EncodeToString(nonce),
		"ciphertext":      base64.RawStdEncoding.EncodeToString(cipherText),
		"ts":              time.Now().UTC().Format(time.RFC3339Nano),
	}
	canon, _ := json.Marshal(secure)
	sig := ed25519.Sign(m.identity.SignPrivate, canon)
	secure["sig"] = base64.RawStdEncoding.EncodeToString(sig)
	data, _ := json.Marshal(secure)
	rep, err := m.rpc.Publish(localrpcclient.PublishArgs{AppID: AppID, Topic: topic, Payload: data})
	if err != nil {
		return err
	}
	if rep.Error != "" {
		return errors.New(rep.Error)
	}
	return nil
}

func encryptForPeer(priv [32]byte, peerPub [32]byte, plain []byte) ([]byte, []byte, error) {
	shared, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return nil, nil, err
	}
	k := sha256.Sum256(shared)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ct := aead.Seal(nil, nonce, plain, nil)
	return ct, nonce, nil
}

func decryptFromPeer(priv [32]byte, peerPub [32]byte, nonce []byte, cipherText []byte) ([]byte, error) {
	shared, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return nil, err
	}
	k := sha256.Sum256(shared)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, cipherText, nil)
}

func generateIdentity() (*Identity, error) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var boxPriv [32]byte
	if _, err := rand.Read(boxPriv[:]); err != nil {
		return nil, err
	}
	boxPubRaw, err := curve25519.X25519(boxPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	var boxPub [32]byte
	copy(boxPub[:], boxPubRaw)
	h := sha256.Sum256(append([]byte("social-user:"), signPub...))
	userID := "u_" + hex.EncodeToString(h[:8])
	return &Identity{UserID: userID, SignPublicKey: signPub, SignPrivate: signPriv, BoxPublicKey: boxPub, BoxPrivateKey: boxPriv}, nil
}

type encryptedIdentityFile struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	MemoryKiB  uint32 `json:"memory_kib"`
	Iterations uint32 `json:"iterations"`
	Parallel   uint8  `json:"parallel"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type identityPlain struct {
	UserID      string `json:"user_id"`
	SignPrivB64 string `json:"sign_priv_b64"`
	BoxPrivB64  string `json:"box_priv_b64"`
}

func (m *Manager) saveIdentity(passphrase string) error {
	if m.identity == nil {
		return errors.New("identity missing")
	}
	plain := identityPlain{
		UserID:      m.identity.UserID,
		SignPrivB64: base64.RawStdEncoding.EncodeToString(m.identity.SignPrivate),
		BoxPrivB64:  base64.RawStdEncoding.EncodeToString(m.identity.BoxPrivateKey[:]),
	}
	payload, _ := json.Marshal(plain)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	iter := uint32(2)
	mem := uint32(64 * 1024)
	par := uint8(1)
	key := argon2.IDKey([]byte(passphrase), salt, iter, mem, par, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := aead.Seal(nil, nonce, payload, nil)
	f := encryptedIdentityFile{Version: 1, KDF: "argon2id", Salt: base64.RawStdEncoding.EncodeToString(salt), MemoryKiB: mem, Iterations: iter, Parallel: par, Nonce: base64.RawStdEncoding.EncodeToString(nonce), Ciphertext: base64.RawStdEncoding.EncodeToString(ct)}
	b, _ := json.MarshalIndent(f, "", "  ")
	return os.WriteFile(filepath.Join(m.cfg.DataDir, "identity.enc.json"), b, 0o600)
}

func (m *Manager) unlock(passphrase string) error {
	if m.identity != nil {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(m.cfg.DataDir, "identity.enc.json"))
	if err != nil {
		return err
	}
	var f encryptedIdentityFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	salt, err := base64.RawStdEncoding.DecodeString(f.Salt)
	if err != nil {
		return err
	}
	nonce, err := base64.RawStdEncoding.DecodeString(f.Nonce)
	if err != nil {
		return err
	}
	ct, err := base64.RawStdEncoding.DecodeString(f.Ciphertext)
	if err != nil {
		return err
	}
	key := argon2.IDKey([]byte(passphrase), salt, f.Iterations, f.MemoryKiB, f.Parallel, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	plainRaw, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return errors.New("invalid passphrase")
	}
	var plain identityPlain
	if err := json.Unmarshal(plainRaw, &plain); err != nil {
		return err
	}
	signPrivRaw, err := base64.RawStdEncoding.DecodeString(plain.SignPrivB64)
	if err != nil {
		return err
	}
	boxPrivRaw, err := base64.RawStdEncoding.DecodeString(plain.BoxPrivB64)
	if err != nil || len(boxPrivRaw) != 32 {
		return errors.New("invalid box key")
	}
	signPriv := ed25519.PrivateKey(signPrivRaw)
	signPub := signPriv.Public().(ed25519.PublicKey)
	boxPubRaw, err := curve25519.X25519(boxPrivRaw, curve25519.Basepoint)
	if err != nil {
		return err
	}
	var boxPriv [32]byte
	copy(boxPriv[:], boxPrivRaw)
	var boxPub [32]byte
	copy(boxPub[:], boxPubRaw)
	m.identity = &Identity{UserID: plain.UserID, SignPublicKey: signPub, SignPrivate: signPriv, BoxPublicKey: boxPub, BoxPrivateKey: boxPriv}
	m.cfg.Passphrase = passphrase
	return nil
}

func (m *Manager) startLoop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startLoopLocked()
}

func (m *Manager) startLoopLocked() {
	if m.cancel != nil || m.profile == nil || m.identity == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	go m.loop(ctx)
	go m.presenceTicker(ctx)
}

func (m *Manager) loop(ctx context.Context) {
	for {
		if err := m.ensureSubscribed(); err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		rep, err := m.rpc.Pull(localrpcclient.PullArgs{AppID: AppID, SubscriptionID: m.subscriptionID, MaxItems: 100, WaitMillis: 2000})
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		if rep.Error != "" {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		for _, msg := range rep.Messages {
			if !m.shouldProcess(msg.Topic, msg.Offset) {
				continue
			}
			m.processRecord(msg)
			m.commitCursor(msg.Topic, msg.Offset)
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (m *Manager) ensureSubscribed() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.subscriptionID != "" {
		return nil
	}
	if m.profile == nil {
		return errors.New("profile missing")
	}
	from := int64(0)
	if len(m.cursors) > 0 {
		from = -1
		for _, v := range m.cursors {
			if from < 0 || v < from {
				from = v
			}
		}
		if from < 0 {
			from = 0
		}
	}
	topics := []string{topicPresence, topicGlobalFeed, inboxTopic(m.profile.UserID)}
	rep, err := m.rpc.Subscribe(localrpcclient.SubscribeArgs{AppID: AppID, Topics: topics, FromOffset: from})
	if err != nil {
		return err
	}
	if rep.Error != "" {
		return errors.New(rep.Error)
	}
	m.subscriptionID = rep.SubscriptionID
	return nil
}

func (m *Manager) shouldProcess(topic string, offset int64) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return offset > m.cursors[topic]
}

func (m *Manager) commitCursor(topic string, offset int64) {
	m.mu.Lock()
	m.cursors[topic] = offset
	subID := m.subscriptionID
	appUser := ""
	if m.profile != nil {
		appUser = m.profile.UserID
	}
	_ = m.saveStateLocked()
	m.mu.Unlock()
	if subID != "" && appUser != "" {
		_, _ = m.rpc.Ack(localrpcclient.AckArgs{AppID: AppID, SubscriptionID: subID, Topic: topic, Offset: offset})
	}
}

func (m *Manager) processRecord(rec localrpcclient.MessageRecord) {
	var generic map[string]any
	if err := json.Unmarshal(rec.Payload, &generic); err != nil {
		return
	}
	kind, _ := generic["kind"].(string)
	switch kind {
	case "plain":
		body, _ := generic["body"].(map[string]any)
		if rec.Topic == topicPresence {
			m.handlePresence(body)
			return
		}
		if rec.Topic == topicGlobalFeed {
			m.handleFeed(body)
			return
		}
	case "secure":
		m.handleSecure(generic)
	}
}

func (m *Manager) handlePresence(body map[string]any) {
	uid := asString(body["user_id"])
	if uid == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.profile != nil && uid == m.profile.UserID {
		return
	}
	m.knownUsers[uid] = KnownUser{
		UserID:        uid,
		Username:      asString(body["username"]),
		Bio:           asString(body["bio"]),
		AvatarData:    asString(body["avatar_data"]),
		SignPublicKey: asString(body["sign_public_key"]),
		BoxPublicKey:  asString(body["box_public_key"]),
		LastSeenAt:    time.Now().UTC(),
	}
	_ = m.saveStateLocked()
}

func (m *Manager) handleFeed(body map[string]any) {
	uid := asString(body["from_user"])
	if uid == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.profile != nil && uid == m.profile.UserID {
		return
	}
	ts, _ := time.Parse(time.RFC3339Nano, asString(body["created_at"]))
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	id := asString(body["message_id"])
	if id != "" {
		if _, ok := m.seenMessageIDs[id]; ok {
			return
		}
		m.seenMessageIDs[id] = struct{}{}
	}
	m.broadcasts = append(m.broadcasts, Broadcast{MessageID: id, FromUser: uid, Text: asString(body["text"]), CreatedAt: ts})
	if len(m.broadcasts) > 400 {
		m.broadcasts = m.broadcasts[len(m.broadcasts)-400:]
	}
	_ = m.saveStateLocked()
}

func (m *Manager) handleSecure(raw map[string]any) {
	m.mu.RLock()
	id := m.identity
	myUser := ""
	if m.profile != nil {
		myUser = m.profile.UserID
	}
	m.mu.RUnlock()
	if id == nil || myUser == "" {
		return
	}
	toUser := asString(raw["to_user_id"])
	if toUser != myUser {
		return
	}
	senderPubB64 := asString(raw["sender_box_pub"])
	senderSignPubB64 := asString(raw["sender_sign_pub"])
	nonceB64 := asString(raw["nonce"])
	cipherB64 := asString(raw["ciphertext"])
	msgID := asString(raw["msg_id"])
	if msgID == "" {
		return
	}
	m.mu.RLock()
	_, seen := m.seenMessageIDs[msgID]
	m.mu.RUnlock()
	if seen {
		return
	}
	senderPubRaw, err := base64.RawStdEncoding.DecodeString(senderPubB64)
	if err != nil || len(senderPubRaw) != 32 {
		return
	}
	senderSignPubRaw, err := base64.RawStdEncoding.DecodeString(senderSignPubB64)
	if err != nil || len(senderSignPubRaw) != ed25519.PublicKeySize {
		return
	}
	sigB64 := asString(raw["sig"])
	sig, err := base64.RawStdEncoding.DecodeString(sigB64)
	if err != nil {
		return
	}
	canonMap := map[string]any{
		"version":         raw["version"],
		"kind":            raw["kind"],
		"msg_id":          raw["msg_id"],
		"from_user_id":    raw["from_user_id"],
		"sender_sign_pub": raw["sender_sign_pub"],
		"sender_box_pub":  raw["sender_box_pub"],
		"to_user_id":      raw["to_user_id"],
		"nonce":           raw["nonce"],
		"ciphertext":      raw["ciphertext"],
		"ts":              raw["ts"],
	}
	canon, _ := json.Marshal(canonMap)
	if !ed25519.Verify(ed25519.PublicKey(senderSignPubRaw), canon, sig) {
		return
	}
	nonce, err := base64.RawStdEncoding.DecodeString(nonceB64)
	if err != nil {
		return
	}
	cipherText, err := base64.RawStdEncoding.DecodeString(cipherB64)
	if err != nil {
		return
	}
	var senderPub [32]byte
	copy(senderPub[:], senderPubRaw)
	plain, err := decryptFromPeer(id.BoxPrivateKey, senderPub, nonce, cipherText)
	if err != nil {
		return
	}
	var body map[string]any
	if err := json.Unmarshal(plain, &body); err != nil {
		return
	}
	msgType := asString(body["type"])
	fromUser := asString(body["from_user_id"])
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seenMessageIDs[msgID] = struct{}{}
	switch msgType {
	case "friend_request":
		if m.profile != nil && !m.profile.Settings.AllowStrangerRequests {
			if _, ok := m.friends[fromUser]; !ok {
				return
			}
		}
		reqID := asString(body["request_id"])
		if reqID == "" {
			return
		}
		if _, exists := m.requests[reqID]; exists {
			return
		}
		created := parseTS(asString(body["created_at"]))
		m.requests[reqID] = FriendRequest{RequestID: reqID, FromUserID: fromUser, ToUserID: myUser, FromName: asString(body["from_name"]), Message: asString(body["message"]), Method: asString(body["method"]), Status: "pending_in", CreatedAt: created, UpdatedAt: created}
	case "friend_response":
		reqID := asString(body["request_id"])
		status := asString(body["status"])
		req, ok := m.requests[reqID]
		if ok {
			req.Status = status
			req.UpdatedAt = time.Now().UTC()
			m.requests[reqID] = req
		}
		if status == "accepted" {
			m.friends[fromUser] = Friend{UserID: fromUser, CreatedAt: time.Now().UTC()}
		}
	case "dm_message":
		msg := DirectMessage{MessageID: asString(body["message_id"]), FromUserID: fromUser, ToUserID: myUser, Body: asString(body["body"]), CreatedAt: parseTS(asString(body["created_at"]))}
		if msg.MessageID == "" {
			msg.MessageID = fmt.Sprintf("dm-in-%d", time.Now().UnixNano())
		}
		if msg.CreatedAt.IsZero() {
			msg.CreatedAt = time.Now().UTC()
		}
		m.dms[fromUser] = append(m.dms[fromUser], msg)
	}
	_ = m.saveStateLocked()
}

func (m *Manager) presenceTicker(ctx context.Context) {
	ticker := time.NewTicker(defaultPresenceEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.publishPresence()
		}
	}
}

func inboxTopic(userID string) string {
	return "app.social.v1.user." + userID + ".inbox"
}

func userIDFromInboxTopic(topic string) string {
	parts := strings.Split(topic, ".")
	if len(parts) >= 6 {
		return parts[4]
	}
	return ""
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func parseTS(raw string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, raw)
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t
}

type persistedState struct {
	Profile         *Profile                   `json:"profile"`
	KnownUsers      map[string]KnownUser       `json:"known_users"`
	Requests        map[string]FriendRequest   `json:"requests"`
	Friends         map[string]Friend          `json:"friends"`
	DMs             map[string][]DirectMessage `json:"dms"`
	Broadcasts      []Broadcast                `json:"broadcasts"`
	UsedInviteNonce map[string]time.Time       `json:"used_invite_nonce"`
	Cursors         map[string]int64           `json:"cursors"`
}

func (m *Manager) stateFile() string { return filepath.Join(m.cfg.DataDir, "state.json") }

func (m *Manager) loadState() error {
	b, err := os.ReadFile(m.stateFile())
	if err != nil {
		return err
	}
	var ps persistedState
	if err := json.Unmarshal(b, &ps); err != nil {
		return err
	}
	m.profile = ps.Profile
	if ps.KnownUsers != nil {
		m.knownUsers = ps.KnownUsers
	}
	if ps.Requests != nil {
		m.requests = ps.Requests
	}
	if ps.Friends != nil {
		m.friends = ps.Friends
	}
	if ps.DMs != nil {
		m.dms = ps.DMs
	}
	m.broadcasts = ps.Broadcasts
	if ps.UsedInviteNonce != nil {
		m.usedInviteNonce = ps.UsedInviteNonce
	}
	if ps.Cursors != nil {
		m.cursors = ps.Cursors
	}
	return nil
}

func (m *Manager) saveStateLocked() error {
	ps := persistedState{
		Profile:         m.profile,
		KnownUsers:      m.knownUsers,
		Requests:        m.requests,
		Friends:         m.friends,
		DMs:             m.dms,
		Broadcasts:      m.broadcasts,
		UsedInviteNonce: m.usedInviteNonce,
		Cursors:         m.cursors,
	}
	b, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(m.stateFile(), b, 0o600); err != nil {
		return err
	}
	m.emitEventLocked("state")
	return nil
}

func (m *Manager) emitEventLocked(event string) {
	for _, ch := range m.listeners {
		select {
		case ch <- event:
		default:
		}
	}
}
