package db

import "testing"

func TestSubdomainStatusBestURL(t *testing.T) {
	cases := []struct {
		name string
		in   SubdomainStatus
		want string
	}{
		{
			name: "https responded → prefer https",
			in:   SubdomainStatus{Subdomain: "a.example.com", HTTPURL: "http://a.example.com", HTTPSURL: "https://a.example.com", HTTPStatus: 200, HTTPSStatus: 200},
			want: "https://a.example.com",
		},
		{
			name: "only http responded → use http",
			in:   SubdomainStatus{Subdomain: "b.example.com", HTTPURL: "http://b.example.com", HTTPSURL: "https://b.example.com", HTTPStatus: 200, HTTPSStatus: 0},
			want: "http://b.example.com",
		},
		{
			name: "no status but https url present → https",
			in:   SubdomainStatus{Subdomain: "c.example.com", HTTPSURL: "https://c.example.com"},
			want: "https://c.example.com",
		},
		{
			name: "bare host only → construct https",
			in:   SubdomainStatus{Subdomain: "d.example.com"},
			want: "https://d.example.com",
		},
		{
			name: "empty → empty",
			in:   SubdomainStatus{},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.BestURL(); got != tc.want {
				t.Errorf("BestURL() = %q, want %q", got, tc.want)
			}
		})
	}
}
