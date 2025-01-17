package core

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClfLog(t *testing.T) {
	tests := []struct {
		name      string
		response  *http.Response
		expectErr bool
	}{
		{
			name: "ValidResponse",
			response: &http.Response{
				Request: &http.Request{
					Host:       "example.com",
					RemoteAddr: "192.168.1.1:12345",
					Method:     "GET",
					URL:        &url.URL{Path: "/path"},
				},
				Proto:         "HTTP/1.1",
				StatusCode:    200,
				ContentLength: 1234,
			},
			expectErr: false,
		},
		{
			name:      "NilResponse",
			response:  nil,
			expectErr: true,
		},
		{
			name: "NilRequest",
			response: &http.Response{
				Request: nil,
			},
			expectErr: true,
		},
		{
			name: "InvalidRemoteAddr",
			response: &http.Response{
				Request: &http.Request{
					Host:       "example.com",
					RemoteAddr: "invalid_remote_addr",
					Method:     "GET",
					URL:        &url.URL{Path: "/path"},
				},
				Proto:         "HTTP/1.1",
				StatusCode:    200,
				ContentLength: 1234,
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ClfLog(tt.response)
			if tt.expectErr {
				assert.NotNil(t, err, "Expected an error but got nil")
			} else {
				assert.Nil(t, err, "Expected no error but got one")
			}
		})
	}
}
