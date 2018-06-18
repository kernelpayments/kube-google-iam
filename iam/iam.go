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

// Credentials represent the security Credentials response.
type Credentials struct {
	Token   string
	Expires time.Time
}

type credentialRequestType int

const (
	credentialRequestTypeAccessToken credentialRequestType = iota
	credentialRequestTypeIDToken
)

type credentialRequest struct {
	Type           credentialRequestType
	ServiceAccount string
	Audience       string
}

func (c *Client) GetAccessToken(serviceAccount string) (*Credentials, error) {
	return c.getCredentials(credentialRequest{
		Type:           credentialRequestTypeAccessToken,
		ServiceAccount: serviceAccount,
	})
}

func (c *Client) GetIDToken(serviceAccount string, audience string) (*Credentials, error) {
	return c.getCredentials(credentialRequest{
		Type:           credentialRequestTypeIDToken,
		ServiceAccount: serviceAccount,
		Audience:       audience,
	})
}

// GetCredentials returns credentials for the given service account.
func (c *Client) getCredentials(req credentialRequest) (*Credentials, error) {
	reqStr, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	item, err := cache.Fetch(string(reqStr), ttl, func() (interface{}, error) {
		return c.getCredentialsUncached(req)
	})
	if err != nil {
		return nil, err
	}
	return item.Value().(*Credentials), nil
}

func (c *Client) getCredentialsUncached(req credentialRequest) (*Credentials, error) {
	claims := map[string]interface{}{
		"iss": req.ServiceAccount,
		"aud": "https://www.googleapis.com/oauth2/v4/token",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	if req.Type == credentialRequestTypeAccessToken {
		claims["scope"] = iam.CloudPlatformScope
	} else if req.Type == credentialRequestTypeIDToken {
		claims["target_audience"] = req.Audience
	} else {
		return nil, fmt.Errorf("Unknown cred request type %d", req.Type)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	jwtReq := &iam.SignJwtRequest{
		Payload: string(payload),
	}
	res, err := c.iamService.Projects.ServiceAccounts.SignJwt("projects/-/serviceAccounts/"+req.ServiceAccount, jwtReq).Do()
	if err != nil {
		return nil, fmt.Errorf("Error signing JWT: %v", err)
	}

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

	var token string
	if req.Type == credentialRequestTypeAccessToken {
		token = tokenRes.AccessToken
	} else if req.Type == credentialRequestTypeIDToken {
		token = tokenRes.IDToken
	}
	return &Credentials{
		Token:   token,
		Expires: time.Now().Add(time.Duration(tokenRes.ExpiresIn) * time.Second),
	}, nil
}
