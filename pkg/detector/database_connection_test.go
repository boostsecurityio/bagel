// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatabaseConnectionDetector_Detect(t *testing.T) {
	det := NewDatabaseConnectionDetector()

	tests := []struct {
		name       string
		content    string
		wantCount  int
		wantScheme string
		wantHost   string
	}{
		{
			name:       "postgres URL with user and password",
			content:    `DATABASE_URL=postgres://alice:hunter2@db.example.com:5432/app`,
			wantCount:  1,
			wantScheme: "postgres",
			wantHost:   "db.example.com:5432",
		},
		{
			name:       "postgresql alternate scheme",
			content:    `DATABASE_URL=postgresql://u:p@h/d`,
			wantCount:  1,
			wantScheme: "postgresql",
			wantHost:   "h",
		},
		{
			name:       "mysql URL",
			content:    `mysql://root:rootpw@localhost:3306/mydb`,
			wantCount:  1,
			wantScheme: "mysql",
			wantHost:   "localhost:3306",
		},
		{
			name:       "mongodb+srv URL",
			content:    `mongodb+srv://user:pw@cluster0.example.mongodb.net/db?retryWrites=true`,
			wantCount:  1,
			wantScheme: "mongodb+srv",
			wantHost:   "cluster0.example.mongodb.net",
		},
		{
			name:       "redis URL with password only",
			content:    `redis://:supersecret@redis.internal:6379/0`,
			wantCount:  1,
			wantScheme: "redis",
			wantHost:   "redis.internal:6379",
		},
		{
			name:       "rediss URL (TLS)",
			content:    `REDIS_URL=rediss://default:abc123@cache.example.com:6380`,
			wantCount:  1,
			wantScheme: "rediss",
			wantHost:   "cache.example.com:6380",
		},
		{
			name:       "amqps URL",
			content:    `amqps://broker:brokerpw@rabbit.example.com:5671/vhost`,
			wantCount:  1,
			wantScheme: "amqps",
			wantHost:   "rabbit.example.com:5671",
		},
		{
			name:      "no userinfo — not a credential",
			content:   `postgres://localhost/mydb`,
			wantCount: 0,
		},
		{
			name:      "username only, no password — not a credential",
			content:   `postgres://alice@db.example.com/app`,
			wantCount: 0,
		},
		{
			name:      "http URL is not a database scheme",
			content:   `https://user:pw@api.example.com/path`,
			wantCount: 0,
		},
		{
			name:      "no schemes at all",
			content:   `JUST_A_REGULAR_STRING=hello`,
			wantCount: 0,
		},
		{
			name: "multiple URLs in one document",
			content: `db1=postgres://a:b@h1/d
db2=mysql://c:d@h2/e`,
			wantCount: 2,
		},
		{
			name:      "duplicate URLs collapse to one finding",
			content:   `postgres://a:b@h/d postgres://a:b@h/d`,
			wantCount: 1,
		},
		{
			name:       "uppercase scheme is detected (RFC 3986 schemes are case-insensitive)",
			content:    `DATABASE_URL=POSTGRES://alice:hunter2@db.example.com:5432/app`,
			wantCount:  1,
			wantScheme: "postgres",
			wantHost:   "db.example.com:5432",
		},
		{
			name:       "mixed-case scheme is detected and scheme metadata is normalized",
			content:    `MySQL://root:rootpw@localhost:3306/mydb`,
			wantCount:  1,
			wantScheme: "mysql",
			wantHost:   "localhost:3306",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := det.Detect(tt.content, testCtx("env:DATABASE_URL"))
			require.Len(t, findings, tt.wantCount)
			if tt.wantCount > 0 && tt.wantScheme != "" {
				f := findings[0]
				assert.Equal(t, "database-connection-string", f.ID)
				assert.Equal(t, "critical", f.Severity)
				assert.Equal(t, tt.wantScheme, f.Metadata["scheme"])
				assert.Equal(t, tt.wantHost, f.Metadata["host"])
			}
		})
	}
}

func TestDatabaseConnectionDetector_Redact(t *testing.T) {
	det := NewDatabaseConnectionDetector()

	tests := []struct {
		name    string
		input   string
		want    string
		wantHit bool
	}{
		{
			name:    "redact password preserves scheme/user/host",
			input:   "DATABASE_URL=postgres://alice:hunter2@db.example.com:5432/app",
			want:    "DATABASE_URL=postgres://alice:[REDACTED-db-credential]@db.example.com:5432/app",
			wantHit: true,
		},
		{
			name:    "redact password-only redis URL",
			input:   "redis://:s3cr3t@cache:6379",
			want:    "redis://:[REDACTED-db-credential]@cache:6379",
			wantHit: true,
		},
		{
			name:    "URL without password is untouched",
			input:   "postgres://localhost/db",
			want:    "postgres://localhost/db",
			wantHit: false,
		},
		{
			name:    "uppercase scheme is redacted too",
			input:   "DB=POSTGRES://alice:hunter2@db.example.com:5432/app",
			want:    "DB=POSTGRES://alice:[REDACTED-db-credential]@db.example.com:5432/app",
			wantHit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, counts := det.Redact(tt.input)
			assert.Equal(t, tt.want, out)
			if tt.wantHit {
				assert.Equal(t, 1, counts["REDACTED-db-credential"])
			} else {
				assert.Zero(t, counts["REDACTED-db-credential"])
			}
		})
	}
}

func TestDatabaseConnectionDetector_Name(t *testing.T) {
	assert.Equal(t, "database-connection-string", NewDatabaseConnectionDetector().Name())
}
