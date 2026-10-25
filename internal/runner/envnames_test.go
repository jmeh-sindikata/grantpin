package runner

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestEnvNames(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		prefix  string
		want    map[string]string
		wantErr error
	}{
		{"empty", nil, "", map[string]string{}, nil},
		{"flat", []string{"API_KEY"}, "", map[string]string{"API_KEY": "API_KEY"}, nil},
		{"lowercase flat", []string{"db_url"}, "", map[string]string{"db_url": "DB_URL"}, nil},
		{"last segment", []string{"aws/access_key"}, "", map[string]string{"aws/access_key": "ACCESS_KEY"}, nil},
		{"deep path", []string{"a/b/c/token"}, "", map[string]string{"a/b/c/token": "TOKEN"}, nil},
		{"dot", []string{"svc/db.url"}, "", map[string]string{"svc/db.url": "DB_URL"}, nil},
		{"dash", []string{"svc/api-key"}, "", map[string]string{"svc/api-key": "API_KEY"}, nil},
		{"dot and dash in flat", []string{"my-app.token"}, "", map[string]string{"my-app.token": "MY_APP_TOKEN"}, nil},
		{"mixed case", []string{"Aws/AccessKey"}, "", map[string]string{"Aws/AccessKey": "ACCESSKEY"}, nil},
		{"leading underscore ok", []string{"x/_hidden"}, "", map[string]string{"x/_hidden": "_HIDDEN"}, nil},
		{
			"no collision keeps short names",
			[]string{"aws/access_key", "gcp/secret"}, "",
			map[string]string{"aws/access_key": "ACCESS_KEY", "gcp/secret": "SECRET"}, nil,
		},
		{
			"collision: both fall back",
			[]string{"aws/access_key", "gcp/access_key"}, "",
			map[string]string{"aws/access_key": "AWS_ACCESS_KEY", "gcp/access_key": "GCP_ACCESS_KEY"}, nil,
		},
		{
			"collision does not affect others",
			[]string{"aws/token", "gcp/token", "db/url"}, "",
			map[string]string{"aws/token": "AWS_TOKEN", "gcp/token": "GCP_TOKEN", "db/url": "URL"}, nil,
		},
		{
			"three-way collision",
			[]string{"a/k", "b/k", "c/k"}, "",
			map[string]string{"a/k": "A_K", "b/k": "B_K", "c/k": "C_K"}, nil,
		},
		{
			"flat name collides with namespaced one",
			[]string{"TOKEN", "aws/token"}, "",
			map[string]string{"TOKEN": "TOKEN", "aws/token": "AWS_TOKEN"}, nil,
		},
		{
			"collision via dot/dash normalisation",
			[]string{"a/x-y", "b/x.y"}, "",
			map[string]string{"a/x-y": "A_X_Y", "b/x.y": "B_X_Y"}, nil,
		},
		{
			"collision by case only",
			[]string{"a/Key", "b/key"}, "",
			map[string]string{"a/Key": "A_KEY", "b/key": "B_KEY"}, nil,
		},
		{"duplicates collapse", []string{"aws/key", "aws/key"}, "", map[string]string{"aws/key": "KEY"}, nil},
		{"prefix", []string{"aws/key", "DB"}, "APP_", map[string]string{"aws/key": "APP_KEY", "DB": "APP_DB"}, nil},
		{
			"prefix applies after fallback",
			[]string{"a/k", "b/k"}, "X_",
			map[string]string{"a/k": "X_A_K", "b/k": "X_B_K"}, nil,
		},
		{"prefix makes leading digit name valid", []string{"x/1"}, "N", map[string]string{"x/1": "N1"}, nil},
		{"lowercase prefix rejected", []string{"x/y"}, "app_", nil, ErrInvalidEnvName},
		{"prefix with dash rejected", []string{"x/y"}, "A-", nil, ErrInvalidEnvName},
		{"leading digit rejected", []string{"db/1"}, "", nil, ErrInvalidEnvName},
		{"digit-leading fallback rejected", []string{"1a/k", "2b/k"}, "", nil, ErrInvalidEnvName},
		{
			"collision survives fallback",
			[]string{"a/x", "b/x", "A_X"}, "", nil, ErrEnvCollision,
		},
		{"fully identical after fallback", []string{"a/Key", "a/key"}, "", nil, ErrEnvCollision},
		{"fallback collides with another short name", []string{"a/b_c", "b/c", "x/c"}, "", nil, ErrEnvCollision},
		{"empty name", []string{""}, "", nil, ErrInvalidSecretName},
		{"space", []string{"a b"}, "", nil, ErrInvalidSecretName},
		{"glob", []string{"aws/*"}, "", nil, ErrInvalidSecretName},
		{"trailing slash", []string{"aws/"}, "", nil, ErrInvalidSecretName},
		{"leading slash", []string{"/aws"}, "", nil, ErrInvalidSecretName},
		{"double slash", []string{"aws//k"}, "", nil, ErrInvalidSecretName},
		{"newline", []string{"a\nb"}, "", nil, ErrInvalidSecretName},
		{"equals", []string{"A=B"}, "", nil, ErrInvalidSecretName},
		{"non-ascii", []string{"é/k"}, "", nil, ErrInvalidSecretName},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EnvNames(tc.in, tc.prefix)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("expected nil map on error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestEnvNamesIndependentOfInputOrder(t *testing.T) {
	a, err := EnvNames([]string{"aws/k", "gcp/k", "z/u"}, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := EnvNames([]string{"z/u", "gcp/k", "aws/k"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("%v != %v", a, b)
	}
}

func TestEnvNamesResultAlwaysValidAndUnique(t *testing.T) {
	names := []string{"a/b", "c/b", "d.e/f-g", "H", "i/J.k", "l-m/n_o"}
	got, err := EnvNames(names, "P_")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for s, e := range got {
		if !posixEnvRE.MatchString(e) || !strings.HasPrefix(e, "P_") {
			t.Errorf("%s -> %q invalid", s, e)
		}
		if seen[e] {
			t.Errorf("duplicate %q", e)
		}
		seen[e] = true
	}
}

func TestEnvNamesErrorsCarryNamesNotValues(t *testing.T) {
	_, err := EnvNames([]string{"a/x", "b/x", "A_X"}, "")
	if err == nil || !strings.Contains(err.Error(), "A_X") {
		t.Fatalf("err = %v", err)
	}
}
