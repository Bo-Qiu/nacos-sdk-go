package security

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nacos-group/nacos-sdk-go/v2/common/constant"
	"github.com/stretchr/testify/assert"
)

// MockHttpAgent implements http_agent.IHttpAgent for testing
type MockHttpAgent struct {
	PostFunc func(url string, header http.Header, timeoutMs uint64, params map[string]string) (*http.Response, error)
}

func (m *MockHttpAgent) Get(url string, header http.Header, timeoutMs uint64, params map[string]string) (*http.Response, error) {
	return nil, nil
}

func (m *MockHttpAgent) Post(url string, header http.Header, timeoutMs uint64, params map[string]string) (*http.Response, error) {
	if m.PostFunc != nil {
		return m.PostFunc(url, header, timeoutMs, params)
	}
	return nil, nil
}

func (m *MockHttpAgent) Delete(url string, header http.Header, timeoutMs uint64, params map[string]string) (*http.Response, error) {
	return nil, nil
}

func (m *MockHttpAgent) Put(url string, header http.Header, timeoutMs uint64, params map[string]string) (*http.Response, error) {
	return nil, nil
}

func (m *MockHttpAgent) Request(method, url string, header http.Header, timeoutMs uint64, params map[string]string) (*http.Response, error) {
	if method == http.MethodPost && m.PostFunc != nil {
		return m.PostFunc(url, header, timeoutMs, params)
	}
	return nil, nil
}

func (m *MockHttpAgent) RequestOnlyResult(method, url string, header http.Header, timeoutMs uint64, params map[string]string) string {
	resp, err := m.Request(method, url, header, timeoutMs, params)
	if err != nil {
		return ""
	}
	if resp == nil || resp.Body == nil {
		return ""
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(data)
}

func TestNacosAuthClient_login(t *testing.T) {
	tests := []struct {
		name           string
		setupClient    func() *NacosAuthClient
		mockResponse   func() (*http.Response, error)
		checkState     func(*testing.T, *NacosAuthClient)
		expectedResult bool
		expectError    bool
	}{
		{
			name: "token before first refresh window (< 3000s)",
			setupClient: func() *NacosAuthClient {
				return &NacosAuthClient{
					lastRefreshTime:    time.Now().Unix(),
					tokenTtl:           3600,
					tokenRefreshWindow: 300,
					accessToken:        &atomic.Value{},
				}
			},
			expectedResult: true,
			expectError:    false,
			checkState: func(t *testing.T, client *NacosAuthClient) {
				assert.True(t, client.lastRefreshTime > 0)
				assert.Equal(t, int64(3600), client.tokenTtl)
				assert.Equal(t, int64(300), client.tokenRefreshWindow)
			},
		},
		{
			name: "token in first refresh window (3000s-3300s)",
			setupClient: func() *NacosAuthClient {
				client := &NacosAuthClient{
					lastRefreshTime:    time.Now().Add(-51 * time.Minute).Unix(), // 3060s old
					tokenTtl:           3600,
					tokenRefreshWindow: 300,
					username:           "testuser",
					password:           "testpass",
					accessToken:        &atomic.Value{},
					clientCfg:          constant.ClientConfig{TimeoutMs: 5000},
				}
				client.accessToken.Store("oldtoken")
				return client
			},
			mockResponse: func() (*http.Response, error) {
				resp := map[string]interface{}{
					"accessToken": "newtoken",
					"tokenTtl":    float64(3600),
				}
				jsonBytes, _ := json.Marshal(resp)
				return &http.Response{
					StatusCode: constant.RESPONSE_CODE_SUCCESS,
					Body:       io.NopCloser(bytes.NewBuffer(jsonBytes)),
				}, nil
			},
			expectedResult: true,
			expectError:    false,
			checkState: func(t *testing.T, client *NacosAuthClient) {
				assert.Equal(t, "newtoken", client.GetAccessToken())
				assert.True(t, client.lastRefreshTime > time.Now().Unix()-5)
			},
		},
		{
			name: "token in second refresh window (3300s-3600s)",
			setupClient: func() *NacosAuthClient {
				client := &NacosAuthClient{
					lastRefreshTime:    time.Now().Add(-56 * time.Minute).Unix(), // 3360s old
					tokenTtl:           3600,
					tokenRefreshWindow: 300,
					username:           "testuser",
					password:           "testpass",
					accessToken:        &atomic.Value{},
					clientCfg:          constant.ClientConfig{TimeoutMs: 5000},
				}
				client.accessToken.Store("oldtoken")
				return client
			},
			mockResponse: func() (*http.Response, error) {
				resp := map[string]interface{}{
					"accessToken": "newtoken",
					"tokenTtl":    float64(3600),
				}
				jsonBytes, _ := json.Marshal(resp)
				return &http.Response{
					StatusCode: constant.RESPONSE_CODE_SUCCESS,
					Body:       io.NopCloser(bytes.NewBuffer(jsonBytes)),
				}, nil
			},
			expectedResult: true,
			expectError:    false,
			checkState: func(t *testing.T, client *NacosAuthClient) {
				assert.Equal(t, "newtoken", client.GetAccessToken())
				assert.True(t, client.lastRefreshTime > time.Now().Unix()-5)
			},
		},
		{
			name: "empty username should return true without refresh",
			setupClient: func() *NacosAuthClient {
				return &NacosAuthClient{
					username:    "",
					accessToken: &atomic.Value{},
				}
			},
			expectedResult: true,
			expectError:    false,
			checkState: func(t *testing.T, client *NacosAuthClient) {
				assert.True(t, client.lastRefreshTime > 0)
			},
		},
		{
			name: "server error should return false",
			setupClient: func() *NacosAuthClient {
				return &NacosAuthClient{
					lastRefreshTime:    time.Now().Add(-56 * time.Minute).Unix(),
					tokenTtl:           3600,
					tokenRefreshWindow: 300,
					username:           "testuser",
					password:           "testpass",
					accessToken:        &atomic.Value{},
					clientCfg:          constant.ClientConfig{TimeoutMs: 5000},
				}
			},
			mockResponse: func() (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(bytes.NewBufferString("Internal Server Error")),
				}, nil
			},
			expectedResult: false,
			expectError:    true,
			checkState: func(t *testing.T, client *NacosAuthClient) {
				assert.Equal(t, "", client.GetAccessToken())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()

			if tt.mockResponse != nil {
				mockAgent := &MockHttpAgent{
					PostFunc: func(url string, header http.Header, timeoutMs uint64, params map[string]string) (*http.Response, error) {
						// Verify request parameters
						assert.Equal(t, []string{"application/x-www-form-urlencoded"}, header["content-type"])
						assert.Equal(t, client.username, params["username"])
						assert.Equal(t, client.password, params["password"])
						return tt.mockResponse()
					},
				}
				client.agent = mockAgent
			}

			serverConfig := constant.ServerConfig{
				Scheme:      "http",
				IpAddr:      "localhost",
				Port:        8848,
				ContextPath: "/nacos",
			}

			result, err := client.login(serverConfig)

			assert.Equal(t, tt.expectedResult, result)
			if tt.expectError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}

			if tt.checkState != nil {
				tt.checkState(t, client)
			}
		})
	}
}

func TestNacosAuthClient_GetAccessToken(t *testing.T) {
	client := &NacosAuthClient{
		accessToken: &atomic.Value{},
	}

	// Test empty token
	assert.Equal(t, "", client.GetAccessToken())

	// Test with token
	client.accessToken.Store("testtoken")
	assert.Equal(t, "testtoken", client.GetAccessToken())
}

func TestNacosAuthClient_GetSecurityInfo(t *testing.T) {
	client := &NacosAuthClient{
		accessToken: &atomic.Value{},
	}

	// Test empty token
	info := client.GetSecurityInfo(RequestResource{})
	assert.Empty(t, info[constant.KEY_ACCESS_TOKEN])

	// Test with token
	client.accessToken.Store("testtoken")
	info = client.GetSecurityInfo(RequestResource{})
	assert.Equal(t, "testtoken", info[constant.KEY_ACCESS_TOKEN])
}

func TestNacosAuthClient_AutoRefresh(t *testing.T) {
	tests := []struct {
		name        string
		setupClient func() *NacosAuthClient
		checkState  func(*testing.T, *NacosAuthClient)
	}{
		{
			name: "auto refresh should trigger at tokenTtl-tokenRefreshWindow",
			setupClient: func() *NacosAuthClient {
				client := &NacosAuthClient{
					username:           "testuser",
					password:           "testpass",
					lastRefreshTime:    time.Now().Unix(),
					tokenTtl:           10, // Small TTL for testing
					tokenRefreshWindow: 2,
					accessToken:        &atomic.Value{},
					clientCfg:          constant.ClientConfig{TimeoutMs: 5000},
					serverCfgs: []constant.ServerConfig{{
						Scheme:      "http",
						IpAddr:      "localhost",
						Port:        8848,
						ContextPath: "/nacos",
					}},
				}
				client.accessToken.Store("oldtoken")
				mockAgent := &MockHttpAgent{
					PostFunc: func(url string, header http.Header, timeoutMs uint64, params map[string]string) (*http.Response, error) {
						resp := map[string]interface{}{
							"accessToken": "newtoken",
							"tokenTtl":    float64(10),
						}
						jsonBytes, _ := json.Marshal(resp)
						return &http.Response{
							StatusCode: constant.RESPONSE_CODE_SUCCESS,
							Body:       io.NopCloser(bytes.NewBuffer(jsonBytes)),
						}, nil
					},
				}
				client.agent = mockAgent
				return client
			},
			checkState: func(t *testing.T, client *NacosAuthClient) {
				// Wait for auto refresh to trigger
				time.Sleep(9 * time.Second)
				assert.Equal(t, "newtoken", client.GetAccessToken())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			client.AutoRefresh(ctx)
			if tt.checkState != nil {
				tt.checkState(t, client)
			}
		})
	}
}
