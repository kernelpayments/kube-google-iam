package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/karlseguin/ccache"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"
	iam "google.golang.org/api/iam/v1"
)

var cache = ccache.New(ccache.Configure())

const (
	maxSessNameLength = 64
	ttl               = time.Minute * 15
)

// Client represents an IAM client.
type Client struct {
	iamService *iam.Service
}

// Credentials represent the security Credentials response.
type Credentials struct {
	AccessToken string
	Expires     time.Time
}

// GetCredentials returns credentials for the given service account.
func (c *Client) GetCredentials(serviceAccount string) (*Credentials, error) {
	item, err := cache.Fetch(serviceAccount, ttl, func() (interface{}, error) {
		return c.getCredentialsUncached(serviceAccount)
	})
	if err != nil {
		return nil, err
	}
	return item.Value().(*Credentials), nil
}

// NewClient returns a new IAM client.
func NewClient() *Client {
	// Authorize the client using Application Default Credentials.
	// See https://g.co/dv/identity/protocols/application-default-credentials
	ctx := context.Background()
	client, err := google.DefaultClient(ctx, iam.CloudPlatformScope)
	if err != nil {
		log.Fatal(err)
	}

	iamService, err := iam.New(client)
	if err != nil {
		log.Fatal(err)
	}

	return &Client{
		iamService: iamService,
	}
}

func (c *Client) getCredentialsUncached(serviceAccount string) (*Credentials, error) {
	payload, err := json.Marshal(jws.ClaimSet{
		Iss:   serviceAccount,
		Aud:   "https://www.googleapis.com/oauth2/v4/token",
		Scope: iam.CloudPlatformScope,
		Exp:   time.Now().Add(time.Hour).Unix(),
		Iat:   time.Now().Unix(),
	})
	if err != nil {
		return nil, err
	}
	req := &iam.SignJwtRequest{
		Payload: string(payload),
	}
	res, err := c.iamService.Projects.ServiceAccounts.SignJwt("projects/-/serviceAccounts/"+serviceAccount, req).Do()
	if err != nil {
		return nil, fmt.Errorf("Error signing JWT: %v", err)
	}
	fmt.Println(res.SignedJwt)

	v := url.Values{}
	v.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	v.Set("assertion", res.SignedJwt)
	resp, err := http.PostForm("https://www.googleapis.com/oauth2/v4/token", v)
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if c := resp.StatusCode; c < 200 || c > 299 {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", resp.Status, body)
	}
	// tokenRes is the JSON response body.
	var tokenRes struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int64  `json:"expires_in"` // relative seconds from now
	}
	if err := json.Unmarshal(body, &tokenRes); err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	return &Credentials{
		AccessToken: tokenRes.AccessToken,
		Expires:     time.Now().Add(time.Duration(tokenRes.ExpiresIn) * time.Second),
	}, nil
}
