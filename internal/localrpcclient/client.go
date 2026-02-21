package localrpcclient

import (
	"net"
	"net/rpc"
	"time"
)

type MessageRecord struct {
	ID        string            `json:"id"`
	Topic     string            `json:"topic"`
	AppID     string            `json:"app_id"`
	Payload   []byte            `json:"payload"`
	Headers   map[string]string `json:"headers,omitempty"`
	Source    string            `json:"source"`
	CreatedAt time.Time         `json:"created_at"`
	Offset    int64             `json:"offset"`
}

type PublishArgs struct {
	AppID   string
	Topic   string
	Payload []byte
	Headers map[string]string
}

type PublishReply struct {
	MessageID string
	Offset    int64
	Accepted  bool
	Error     string
}

type SubscribeArgs struct {
	AppID      string
	Topics     []string
	FromOffset int64
}

type SubscribeReply struct {
	SubscriptionID string
	Error          string
}

type PullArgs struct {
	AppID          string
	SubscriptionID string
	MaxItems       int
	WaitMillis     int
}

type PullReply struct {
	Messages []MessageRecord
	Error    string
}

type AckArgs struct {
	AppID          string
	SubscriptionID string
	Topic          string
	Offset         int64
}

type AckReply struct {
	OK    bool
	Error string
}

type HistoryArgs struct {
	AppID      string
	Topic      string
	FromOffset int64
	Limit      int
}

type HistoryReply struct {
	Messages []MessageRecord
	Error    string
}

type StatusArgs struct{}

type StatusReply struct {
	Transport      string
	PeerID         string
	ConnectedPeers int
	Error          string
}

type Client struct {
	socketPath string
	timeout    time.Duration
}

func New(socketPath string) *Client {
	return &Client{socketPath: socketPath, timeout: 5 * time.Second}
}

func (c *Client) call(method string, args any, reply any) error {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	cli := rpc.NewClient(conn)
	defer cli.Close()
	return cli.Call(method, args, reply)
}

func (c *Client) Publish(args PublishArgs) (PublishReply, error) {
	var out PublishReply
	err := c.call("P2P.Publish", args, &out)
	return out, err
}

func (c *Client) Subscribe(args SubscribeArgs) (SubscribeReply, error) {
	var out SubscribeReply
	err := c.call("P2P.Subscribe", args, &out)
	return out, err
}

func (c *Client) Pull(args PullArgs) (PullReply, error) {
	var out PullReply
	err := c.call("P2P.Pull", args, &out)
	return out, err
}

func (c *Client) Ack(args AckArgs) (AckReply, error) {
	var out AckReply
	err := c.call("P2P.Ack", args, &out)
	return out, err
}

func (c *Client) FetchHistory(args HistoryArgs) (HistoryReply, error) {
	var out HistoryReply
	err := c.call("P2P.FetchHistory", args, &out)
	return out, err
}

func (c *Client) GetStatus() (StatusReply, error) {
	var out StatusReply
	err := c.call("P2P.GetStatus", StatusArgs{}, &out)
	return out, err
}
