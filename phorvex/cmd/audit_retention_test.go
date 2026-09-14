package main

import "testing"

func TestAuditRetentionDefaults(t *testing.T) {
	if defaultAuditMaxBytes != 512<<20 || defaultAuditMaxBackups != 4 {
		t.Fatalf("audit defaults bytes=%d backups=%d", defaultAuditMaxBytes, defaultAuditMaxBackups)
	}
	if got := defaultAuditMaxBytes * int64(defaultAuditMaxBackups+1); got != 2560<<20 {
		t.Fatalf("nominal retention budget=%d want=%d", got, int64(2560<<20))
	}
}
