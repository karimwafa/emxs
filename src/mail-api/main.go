package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httputil"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

type DashboardUser struct {
	ID           int        `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"`
	Role         string     `json:"role"`
	OTPEnabled   bool       `json:"otp_enabled"`
	OTPSecret    string     `json:"otp_secret,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLogin    *time.Time `json:"last_login"`
}

type DashboardSession struct {
	ID        int       `json:"id"`
	Token     string    `json:"token"`
	UserID    int       `json:"user_id"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type Domain struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UserCount int       `json:"user_count"`
}

type Account struct {
	ID         int       `json:"id"`
	DomainID   int       `json:"domain_id"`
	DomainName string    `json:"domain_name,omitempty"`
	Username   string    `json:"username"`
	Email      string    `json:"email"`
	QuotaBytes int64     `json:"quota_bytes"`
	UsedBytes  int64     `json:"used_bytes"`
	IsActive   bool      `json:"is_active"`
	CreatedAt  time.Time `json:"created_at"`
}

type Alias struct {
	ID          int       `json:"id"`
	DomainID    int       `json:"domain_id"`
	DomainName  string    `json:"domain_name,omitempty"`
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
}

type DKIMResult struct {
	Domain    string `json:"domain"`
	Selector  string `json:"selector"`
	DNSRecord string `json:"dns_record"`
	DNSType   string `json:"dns_type"`
	DNSHost   string `json:"dns_host"`
}

type ServiceStatus struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
	Port    string `json:"port"`
}

type SystemStats struct {
	TotalDomains  int             `json:"total_domains"`
	TotalAccounts int             `json:"total_accounts"`
	TotalAliases  int             `json:"total_aliases"`
	QueueCount    int             `json:"queue_count"`
	DiskUsed      string          `json:"disk_used"`
	DiskAvail     string          `json:"disk_avail"`
	DiskPercent   string          `json:"disk_percent"`
	Uptime        string          `json:"uptime"`
	Services      []ServiceStatus `json:"services"`
}

type DNSCheckResult struct {
	Domain      string   `json:"domain"`
	MXValid     bool     `json:"mx_valid"`
	MXRecords   []string `json:"mx_records"`
	SPFValid    bool     `json:"spf_valid"`
	SPFRecord   string   `json:"spf_record"`
	DKIMValid   bool     `json:"dkim_valid"`
	DKIMRecord  string   `json:"dkim_record"`
	DMARCValid  bool     `json:"dmarc_valid"`
	DMARCRecord string   `json:"dmarc_record"`
}

type QueueItem struct {
	ID        string `json:"id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Size      string `json:"size"`
	Date      string `json:"date"`
	Reason    string `json:"reason"`
}

type MailMessage struct {
	ID       string `json:"id"`
	From     string `json:"from"`
	To       string `json:"to"`
	Subject  string `json:"subject"`
	Date     string `json:"date"`
	Snippet  string `json:"snippet"`
	Body     string `json:"body"`
	Filename string `json:"filename"`
}

type EmailTransaction struct {
	ID        int     `json:"id"`
	Timestamp string  `json:"timestamp"`
	MessageID string  `json:"message_id"`
	Sender    string  `json:"sender"`
	Recipient string  `json:"recipient"`
	Subject   string  `json:"subject"`
	Status    string  `json:"status"`
	Direction string  `json:"direction"`
	ClientIP  string  `json:"client_ip"`
	SizeBytes int64   `json:"size_bytes"`
	SpamScore float64 `json:"spam_score"`
	Details   string  `json:"details"`
}

type TransactionStats struct {
	TotalMonth       int               `json:"total_month"`
	TotalDelivered   int               `json:"total_delivered"`
	TotalSent        int               `json:"total_sent"`
	TotalRejected    int               `json:"total_rejected"`
	TotalSpam        int               `json:"total_spam"`
	ArchivedFiles    int               `json:"archived_files"`
	ArchivedBytes    int64             `json:"archived_bytes"`
	LastArchiveDate  string            `json:"last_archive_date"`
	MaxRetentionDays int               `json:"max_retention_days"`
	ArchivesList     []ArchiveFileInfo `json:"archives_list"`
}

type ArchiveFileInfo struct {
	Filename string `json:"filename"`
	SizeKB   string `json:"size_kb"`
	ModTime  string `json:"mod_time"`
}

var (
	startTime        = time.Now()
	configuredHost   = "mail.elsw-studio.my.id"
	configuredDomain = "elsw-studio.my.id"
	configuredIP     = "103.147.157.37"
)

func main() {
	if h := os.Getenv("EMXS_SERVER_HOST"); h != "" {
		configuredHost = h
	}
	if d := os.Getenv("EMXS_PRIMARY_DOMAIN"); d != "" {
		configuredDomain = d
	} else if strings.HasPrefix(configuredHost, "mail.") {
		configuredDomain = strings.TrimPrefix(configuredHost, "mail.")
	}
	if ip := os.Getenv("EMXS_SERVER_IP"); ip != "" {
		configuredIP = ip
	}

	connStr := os.Getenv("EMXS_DB_CONN")
	if connStr == "" {
		connStr = "host=localhost port=5432 user=mailuser password=MailSec_P0stgre_2026!k9 dbname=mailserver sslmode=disable"
	}

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := initDashboardDB(); err != nil {
		log.Printf("[Dashboard Auth] DB initialization warning: %v", err)
	}

	// Clean expired sessions hourly
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			cleanupExpiredSessions()
		}
	}()

	mux := http.NewServeMux()

	// Auth & User Management APIs
	mux.HandleFunc("/api/auth/login", handleLogin)
	mux.HandleFunc("/api/auth/logout", handleLogout)
	mux.HandleFunc("/api/auth/me", requireAuth(handleAuthMe))
	mux.HandleFunc("/api/auth/otp/setup", requireAuth(handleOTPSetup))
	mux.HandleFunc("/api/auth/otp/toggle", requireAuth(handleOTPToggle))
	mux.HandleFunc("/api/dashboard-users", requireAuth(handleDashboardUsers))
	mux.HandleFunc("/api/dashboard-users/password", requireAuth(handleUserPasswordReset))

	// REST APIs (Protected)
	mux.HandleFunc("/api/domains", requireAuth(handleDomains))
	mux.HandleFunc("/api/accounts", requireAuth(handleAccounts))
	mux.HandleFunc("/api/accounts/password", requireAuth(handleAccountPassword))
	mux.HandleFunc("/api/aliases", requireAuth(handleAliases))
	mux.HandleFunc("/api/dkim/generate", requireAuth(handleDKIM))
	mux.HandleFunc("/api/stats", requireAuth(handleStats))
	mux.HandleFunc("/api/dns/check", requireAuth(handleDNSCheck))
	mux.HandleFunc("/api/queue", requireAuth(handleQueue))
	mux.HandleFunc("/api/queue/flush", requireAuth(handleQueueFlush))
	mux.HandleFunc("/api/queue/delete", requireAuth(handleQueueDelete))
	mux.HandleFunc("/api/logs", requireAuth(handleLogs))
	mux.HandleFunc("/api/filter/rules", requireAuth(handleFilterRules))

	// Email Transaction History & Archiving APIs (Protected)
	mux.HandleFunc("/api/transactions", requireAuth(handleTransactions))
	mux.HandleFunc("/api/transactions/stats", requireAuth(handleTransactionStats))
	mux.HandleFunc("/api/transactions/archive", requireAuth(handleManualArchive))

	// Background Transaction Sync & Auto-Archiving (>30 days compressed to /var/log/mail_archives/)
	go func() {
		time.Sleep(2 * time.Second)
		syncAllTransactions()
		_, _ = archiveOldTransactions()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			syncAllTransactions()
			_, _ = archiveOldTransactions()
		}
	}()

	// Webmail APIs (Send & Read - Protected)
	mux.HandleFunc("/api/webmail/send", requireAuth(handleWebmailSend))
	mux.HandleFunc("/api/webmail/inbox", requireAuth(handleWebmailInbox))
	mux.HandleFunc("/api/webmail/read", requireAuth(handleWebmailRead))

	// Roundcube Webmail Reverse Proxy (Port 8088)
	rcTarget, _ := url.Parse("http://127.0.0.1:8088")
	rcProxy := httputil.NewSingleHostReverseProxy(rcTarget)
	origDirector := rcProxy.Director
	rcProxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-For", req.RemoteAddr)
		req.Header.Set("X-Forwarded-Host", req.Host)
	}

	mux.HandleFunc("/webmail/", func(w http.ResponseWriter, r *http.Request) {
		rcProxy.ServeHTTP(w, r)
	})
	mux.HandleFunc("/webmail", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/webmail/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/skins/", func(w http.ResponseWriter, r *http.Request) {
		rcProxy.ServeHTTP(w, r)
	})
	mux.HandleFunc("/plugins/", func(w http.ResponseWriter, r *http.Request) {
		rcProxy.ServeHTTP(w, r)
	})
	mux.HandleFunc("/program/", func(w http.ResponseWriter, r *http.Request) {
		rcProxy.ServeHTTP(w, r)
	})
	mux.HandleFunc("/assets/", func(w http.ResponseWriter, r *http.Request) {
		rcProxy.ServeHTTP(w, r)
	})

	// Favicon & Branding Icons
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFile(w, r, "/var/www/emxs_icons/favicon.ico")
	})
	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFile(w, r, "/var/www/emxs_icons/favicon.svg")
	})
	mux.HandleFunc("/favicon.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFile(w, r, "/var/www/emxs_icons/favicon.png")
	})
	mux.HandleFunc("/favicon-32x32.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFile(w, r, "/var/www/emxs_icons/favicon-32x32.png")
	})
	mux.HandleFunc("/favicon-16x16.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFile(w, r, "/var/www/emxs_icons/favicon-16x16.png")
	})
	mux.HandleFunc("/apple-touch-icon.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFile(w, r, "/var/www/emxs_icons/apple-touch-icon.png")
	})

	// Web Dashboard
	mux.HandleFunc("/", handleDashboard)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	certFile := os.Getenv("EMXS_SSL_CERT")
	keyFile := os.Getenv("EMXS_SSL_KEY")
	if certFile == "" || keyFile == "" {
		candidates := []string{
			filepath.Join("/etc/letsencrypt/live", configuredHost, "fullchain.pem"),
			"/etc/emxs/ssl/fullchain.pem",
			"/etc/letsencrypt/live/mail.elsw-studio.my.id/fullchain.pem",
		}
		keyCandidates := []string{
			filepath.Join("/etc/letsencrypt/live", configuredHost, "privkey.pem"),
			"/etc/emxs/ssl/privkey.pem",
			"/etc/letsencrypt/live/mail.elsw-studio.my.id/privkey.pem",
		}
		for i := range candidates {
			if _, err := os.Stat(candidates[i]); err == nil {
				if _, err := os.Stat(keyCandidates[i]); err == nil {
					certFile = candidates[i]
					keyFile = keyCandidates[i]
					break
				}
			}
		}
	}

	hasCert := false
	if certFile != "" && keyFile != "" {
		if _, err := os.Stat(certFile); err == nil {
			if _, err := os.Stat(keyFile); err == nil {
				hasCert = true
			}
		}
	}

	handler := corsMiddleware(mux)

	if hasCert {
		log.Printf("Let's Encrypt SSL found. Starting servers on Port 443 (HTTPS), 8080 (HTTPS), and 80 (HTTP redirect)...")

		// Port 443 (Standard HTTPS)
		go func() {
			log.Printf("Starting HTTPS on :443")
			if err := http.ListenAndServeTLS(":443", certFile, keyFile, handler); err != nil {
				log.Printf("Port 443 error: %v", err)
			}
		}()

		// Port 80 (HTTP redirect to HTTPS)
		go func() {
			_ = http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.URL.Path
				if r.URL.RawQuery != "" {
					target += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			}))
		}()

		// Port 8080 (HTTPS)
		log.Printf("Starting HTTPS on :%s", port)
		if err := http.ListenAndServeTLS(":"+port, certFile, keyFile, handler); err != nil {
			log.Fatalf("TLS error on :%s: %v", port, err)
		}
	} else {
		log.Printf("Starting plain HTTP on :%s", port)
		if err := http.ListenAndServe(":"+port, handler); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		log.Printf("[HTTP] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func execTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

func isServiceActive(name string) bool {
	out, err := execTimeout(1500*time.Millisecond, "systemctl", "is-active", name)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var totalDomains, totalAccounts, totalAliases int
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM domains").Scan(&totalDomains)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM accounts").Scan(&totalAccounts)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM aliases").Scan(&totalAliases)

	queueCount := 0
	out, err := execTimeout(2*time.Second, "postqueue", "-p")
	if err == nil {
		str := string(out)
		if !strings.Contains(str, "Mail queue is empty") {
			lines := strings.Split(str, "\n")
			for _, line := range lines {
				if strings.Contains(line, "--") && strings.Contains(line, "Kbytes") {
					fields := strings.Fields(line)
					if len(fields) > 4 {
						count, _ := strconv.Atoi(fields[4])
						queueCount = count
					}
				}
			}
		}
	}

	diskUsed, diskAvail, diskPercent := "0", "0", "0%"
	dfOut, err := execTimeout(2*time.Second, "df", "-h", "/var/mail/vhosts")
	if err == nil {
		lines := strings.Split(string(dfOut), "\n")
		if len(lines) > 1 {
			f := strings.Fields(lines[1])
			if len(f) >= 5 {
				diskUsed = f[2]
				diskAvail = f[3]
				diskPercent = f[4]
			}
		}
	}

	services := []ServiceStatus{
		{Name: "Postfix MTA", Running: isServiceActive("postfix"), Port: "SMTP 25, 465, 587"},
		{Name: "Dovecot Storage & IMAP", Running: isServiceActive("dovecot"), Port: "IMAP 993, 143, POP3"},
		{Name: "Rspamd Security Engine", Running: isServiceActive("rspamd"), Port: "Milter 11332 (DKIM/Spam)"},
		{Name: "PostgreSQL Database", Running: isServiceActive("postgresql"), Port: "TCP 5432"},
		{Name: "Redis In-Memory Cache", Running: isServiceActive("redis-server"), Port: "TCP 6379"},
	}

	jsonResponse(w, http.StatusOK, SystemStats{
		TotalDomains:  totalDomains,
		TotalAccounts: totalAccounts,
		TotalAliases:  totalAliases,
		QueueCount:    queueCount,
		DiskUsed:      diskUsed,
		DiskAvail:     diskAvail,
		DiskPercent:   diskPercent,
		Uptime:        time.Since(startTime).Round(time.Second).String(),
		Services:      services,
	})
}

func handleDomains(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		rows, err := db.QueryContext(ctx, `
			SELECT d.id, d.name, d.is_active, d.created_at, COUNT(a.id)
			FROM domains d
			LEFT JOIN accounts a ON d.id = a.domain_id
			GROUP BY d.id
			ORDER BY d.id ASC
		`)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var domains []Domain
		for rows.Next() {
			var d Domain
			if err := rows.Scan(&d.ID, &d.Name, &d.IsActive, &d.CreatedAt, &d.UserCount); err == nil {
				domains = append(domains, d)
			}
		}
		jsonResponse(w, http.StatusOK, domains)

	case "POST":
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid domain name"})
			return
		}
		name := strings.ToLower(strings.TrimSpace(req.Name))
		var id int
		err := db.QueryRow("INSERT INTO domains (name) VALUES ($1) RETURNING id", name).Scan(&id)
		if err != nil {
			jsonResponse(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}

		go generateDKIMKey(name, id)

		jsonResponse(w, http.StatusCreated, map[string]interface{}{"id": id, "name": name, "message": "Domain created & DKIM key generated"})

	case "DELETE":
		idStr := r.URL.Query().Get("id")
		id, _ := strconv.Atoi(idStr)
		if id <= 0 {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing or invalid id"})
			return
		}
		_, err := db.Exec("DELETE FROM domains WHERE id = $1", id)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{"message": "Domain deleted successfully"})

	default:
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
	}
}

func handleAccounts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		rows, err := db.QueryContext(ctx, `
			SELECT a.id, a.domain_id, d.name, a.username, a.email, a.quota_bytes, a.is_active, a.created_at
			FROM accounts a
			JOIN domains d ON a.domain_id = d.id
			ORDER BY a.id ASC
		`)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var accounts []Account
		for rows.Next() {
			var a Account
			if err := rows.Scan(&a.ID, &a.DomainID, &a.DomainName, &a.Username, &a.Email, &a.QuotaBytes, &a.IsActive, &a.CreatedAt); err == nil {
				dirPath := filepath.Join("/var/mail/vhosts", a.DomainName, a.Username)
				var used int64 = 0
				duOut, err := execTimeout(1*time.Second, "du", "-sb", dirPath)
				if err == nil {
					f := strings.Fields(string(duOut))
					if len(f) > 0 {
						used, _ = strconv.ParseInt(f[0], 10, 64)
					}
				}
				a.UsedBytes = used
				accounts = append(accounts, a)
			}
		}
		jsonResponse(w, http.StatusOK, accounts)

	case "POST":
		var req struct {
			DomainID int    `json:"domain_id"`
			Username string `json:"username"`
			Password string `json:"password"`
			QuotaGB  int64  `json:"quota_gb"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DomainID <= 0 || req.Username == "" || req.Password == "" {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing required fields"})
			return
		}

		var domainName string
		err := db.QueryRow("SELECT name FROM domains WHERE id = $1", req.DomainID).Scan(&domainName)
		if err != nil {
			jsonResponse(w, http.StatusNotFound, map[string]string{"error": "Domain not found"})
			return
		}

		user := strings.ToLower(strings.TrimSpace(req.Username))
		email := fmt.Sprintf("%s@%s", user, domainName)

		hashBytes, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to hash password"})
			return
		}
		hashedPassword := fmt.Sprintf("{BLF-CRYPT}%s", string(hashBytes))

		quotaBytes := int64(10 * 1024 * 1024 * 1024)
		if req.QuotaGB > 0 {
			quotaBytes = req.QuotaGB * 1024 * 1024 * 1024
		}

		var id int
		err = db.QueryRow(`
			INSERT INTO accounts (domain_id, username, email, password, quota_bytes)
			VALUES ($1, $2, $3, $4, $5) RETURNING id
		`, req.DomainID, user, email, hashedPassword, quotaBytes).Scan(&id)
		if err != nil {
			jsonResponse(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}

		// Ensure Maildir directory exists with correct permissions
		maildir := filepath.Join("/var/mail/vhosts", domainName, user)
		_ = os.MkdirAll(filepath.Join(maildir, "cur"), 0770)
		_ = os.MkdirAll(filepath.Join(maildir, "new"), 0770)
		_ = os.MkdirAll(filepath.Join(maildir, "tmp"), 0770)
		_ = exec.Command("chown", "-R", "vmail:vmail", maildir).Run()

		jsonResponse(w, http.StatusCreated, map[string]interface{}{
			"id":      id,
			"email":   email,
			"message": "Mailbox account created successfully",
		})

	case "DELETE":
		idStr := r.URL.Query().Get("id")
		id, _ := strconv.Atoi(idStr)
		if id <= 0 {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing or invalid id"})
			return
		}
		_, err := db.Exec("DELETE FROM accounts WHERE id = $1", id)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{"message": "Mailbox deleted successfully"})

	default:
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
	}
}

func handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	var req struct {
		ID       int    `json:"id"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID <= 0 || req.Password == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to hash password"})
		return
	}
	hashedPassword := fmt.Sprintf("{BLF-CRYPT}%s", string(hashBytes))

	_, err = db.Exec("UPDATE accounts SET password = $1 WHERE id = $2", hashedPassword, req.ID)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "Password updated successfully"})
}

func handleAliases(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		rows, err := db.QueryContext(ctx, `
			SELECT a.id, a.domain_id, d.name, a.source, a.destination, a.is_active, a.created_at
			FROM aliases a
			JOIN domains d ON a.domain_id = d.id
			ORDER BY a.id ASC
		`)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		aliases := []Alias{}
		for rows.Next() {
			var a Alias
			if err := rows.Scan(&a.ID, &a.DomainID, &a.DomainName, &a.Source, &a.Destination, &a.IsActive, &a.CreatedAt); err == nil {
				aliases = append(aliases, a)
			}
		}
		jsonResponse(w, http.StatusOK, aliases)

	case "POST":
		var req struct {
			DomainID    int    `json:"domain_id"`
			Source      string `json:"source"`
			Destination string `json:"destination"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DomainID <= 0 || req.Source == "" || req.Destination == "" {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing required fields"})
			return
		}

		var id int
		err := db.QueryRow("INSERT INTO aliases (domain_id, source, destination) VALUES ($1, $2, $3) RETURNING id",
			req.DomainID, strings.ToLower(strings.TrimSpace(req.Source)), strings.TrimSpace(req.Destination)).Scan(&id)
		if err != nil {
			jsonResponse(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		jsonResponse(w, http.StatusCreated, map[string]interface{}{"id": id, "message": "Alias created successfully"})

	case "DELETE":
		idStr := r.URL.Query().Get("id")
		id, _ := strconv.Atoi(idStr)
		if id <= 0 {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing or invalid id"})
			return
		}
		_, err := db.Exec("DELETE FROM aliases WHERE id = $1", id)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{"message": "Alias deleted successfully"})

	default:
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
	}
}

func generateDKIMKey(domain string, domainID int) (*DKIMResult, error) {
	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return nil, err
	}

	privASN1 := x509.MarshalPKCS1PrivateKey(key)
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privASN1,
	}
	privPEM := string(pem.EncodeToMemory(privBlock))

	pubASN1, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	pubBase64 := base64.StdEncoding.EncodeToString(pubASN1)

	selector := "appsmail"
	dnsRecord := fmt.Sprintf("v=DKIM1; k=rsa; p=%s", pubBase64)
	dnsHost := fmt.Sprintf("%s._domainkey.%s", selector, domain)

	dkimDir := "/var/lib/rspamd/dkim"
	_ = os.MkdirAll(dkimDir, 0750)
	keyPath := filepath.Join(dkimDir, fmt.Sprintf("%s.%s.key", domain, selector))
	if err := os.WriteFile(keyPath, []byte(privPEM), 0640); err == nil {
		_ = exec.Command("chown", "_rspamd:_rspamd", keyPath).Run()
	}

	_, _ = db.Exec(`
		INSERT INTO dkim_keys (domain_id, selector, private_key, public_key, dns_record)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (domain_id) DO UPDATE SET selector = $2, private_key = $3, public_key = $4, dns_record = $5
	`, domainID, selector, privPEM, pubBase64, dnsRecord)

	return &DKIMResult{
		Domain:    domain,
		Selector:  selector,
		DNSRecord: dnsRecord,
		DNSType:   "TXT",
		DNSHost:   dnsHost,
	}, nil
}

func handleDKIM(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" && r.Method != "GET" {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	if domain == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Query param 'domain' required"})
		return
	}

	var domainID int
	err := db.QueryRow("SELECT id FROM domains WHERE name = $1", domain).Scan(&domainID)
	if err != nil {
		jsonResponse(w, http.StatusNotFound, map[string]string{"error": "Domain not found"})
		return
	}

	if r.Method == "GET" {
		var selector, dnsRecord string
		err := db.QueryRow("SELECT selector, dns_record FROM dkim_keys WHERE domain_id = $1", domainID).Scan(&selector, &dnsRecord)
		if err == nil && selector == "appsmail" {
			jsonResponse(w, http.StatusOK, DKIMResult{
				Domain:    domain,
				Selector:  selector,
				DNSRecord: dnsRecord,
				DNSType:   "TXT",
				DNSHost:   fmt.Sprintf("%s._domainkey.%s", selector, domain),
			})
			return
		}
	}

	res, err := generateDKIMKey(domain, domainID)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	jsonResponse(w, http.StatusOK, res)
}

func handleDNSCheck(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	if domain == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Query param 'domain' required"})
		return
	}

	res := DNSCheckResult{Domain: domain}

	mxs, err := net.LookupMX(domain)
	if err == nil && len(mxs) > 0 {
		res.MXValid = true
		for _, mx := range mxs {
			res.MXRecords = append(res.MXRecords, fmt.Sprintf("%s (pri: %d)", mx.Host, mx.Pref))
		}
	}

	txts, err := net.LookupTXT(domain)
	if err == nil {
		for _, t := range txts {
			if strings.HasPrefix(t, "v=spf1") {
				res.SPFValid = true
				res.SPFRecord = t
				break
			}
		}
	}

	dkimHost := fmt.Sprintf("appsmail._domainkey.%s", domain)
	dkimTxts, err := net.LookupTXT(dkimHost)
	if err == nil && len(dkimTxts) > 0 {
		res.DKIMValid = true
		res.DKIMRecord = strings.Join(dkimTxts, "")
	}

	dmarcHost := fmt.Sprintf("_dmarc.%s", domain)
	dmarcTxts, err := net.LookupTXT(dmarcHost)
	if err == nil && len(dmarcTxts) > 0 {
		for _, dt := range dmarcTxts {
			if strings.HasPrefix(dt, "v=DMARC1") {
				res.DMARCValid = true
				res.DMARCRecord = dt
				break
			}
		}
	}

	jsonResponse(w, http.StatusOK, res)
}

func handleQueue(w http.ResponseWriter, r *http.Request) {
	out, err := execTimeout(2*time.Second, "postqueue", "-p")
	if err != nil {
		jsonResponse(w, http.StatusOK, []QueueItem{})
		return
	}

	str := string(out)
	if strings.Contains(str, "Mail queue is empty") {
		jsonResponse(w, http.StatusOK, []QueueItem{})
		return
	}

	var items []QueueItem
	lines := strings.Split(str, "\n")
	var current QueueItem

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-Queue ID-") || strings.Contains(line, "Kbytes in") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 7 && (len(parts[0]) == 10 || len(parts[0]) == 11) {
			if current.ID != "" {
				items = append(items, current)
			}
			current = QueueItem{
				ID:     parts[0],
				Size:   parts[1],
				Date:   parts[2] + " " + parts[3] + " " + parts[4],
				Sender: parts[6],
			}
		} else if strings.HasPrefix(line, "(") && strings.HasSuffix(line, ")") {
			current.Reason = strings.Trim(line, "()")
		} else if strings.Contains(line, "@") {
			current.Recipient = line
		}
	}
	if current.ID != "" {
		items = append(items, current)
	}

	jsonResponse(w, http.StatusOK, items)
}

func handleQueueFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	err := exec.Command("postqueue", "-f").Run()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "Mail queue flush triggered successfully"})
}

func handleQueueDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "ALL"
	}
	err := exec.Command("postsuper", "-d", id).Run()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("Queue item %s deleted", id)})
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	linesCount := r.URL.Query().Get("lines")
	if linesCount == "" {
		linesCount = "100"
	}
	out, err := execTimeout(3*time.Second, "journalctl", "-u", "postfix", "-u", "dovecot", "-u", "rspamd", "-n", linesCount, "--no-pager")
	if err != nil {
		jsonResponse(w, http.StatusOK, map[string]string{"logs": "Unable to fetch logs at this moment: " + err.Error()})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"logs": string(out)})
}

type FilterRules struct {
	BadExtensions    []string `json:"bad_extensions"`
	BlacklistSenders []string `json:"blacklist_senders"`
	WhitelistSenders []string `json:"whitelist_senders"`
	BadSubjects      []string `json:"bad_subjects"`
	ScoreReject      float64  `json:"score_reject"`
	ScoreAddHeader   float64  `json:"score_add_header"`
	ScoreGreylist    float64  `json:"score_greylist"`
}

func readFilterLines(path string) []string {
	var lines []string
	f, err := os.Open(path)
	if err != nil {
		return lines
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" && !strings.HasPrefix(text, "#") {
			lines = append(lines, text)
		}
	}
	return lines
}

func writeFilterLines(path string, lines []string) error {
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	var content string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			content += l + "\n"
		}
	}
	return os.WriteFile(path, []byte(content), 0644)
}

func handleFilterRules(w http.ResponseWriter, r *http.Request) {
	extPath := "/etc/rspamd/maps.d/bad_extensions.map"
	blPath := "/etc/rspamd/maps.d/blacklist_senders.map"
	wlPath := "/etc/rspamd/maps.d/whitelist_senders.map"
	subPath := "/etc/rspamd/maps.d/bad_subjects.map"
	actPath := "/etc/rspamd/local.d/actions.conf"

	switch r.Method {
	case "GET":
		scoreReject := 15.0
		scoreHeader := 6.0
		scoreGrey := 4.0
		if actData, err := os.ReadFile(actPath); err == nil {
			str := string(actData)
			for _, line := range strings.Split(str, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "reject") {
					parts := strings.Split(line, "=")
					if len(parts) == 2 {
						v := strings.Trim(strings.TrimSpace(parts[1]), ";")
						if f, err := strconv.ParseFloat(v, 64); err == nil {
							scoreReject = f
						}
					}
				} else if strings.HasPrefix(line, "add_header") {
					parts := strings.Split(line, "=")
					if len(parts) == 2 {
						v := strings.Trim(strings.TrimSpace(parts[1]), ";")
						if f, err := strconv.ParseFloat(v, 64); err == nil {
							scoreHeader = f
						}
					}
				} else if strings.HasPrefix(line, "greylist") {
					parts := strings.Split(line, "=")
					if len(parts) == 2 {
						v := strings.Trim(strings.TrimSpace(parts[1]), ";")
						if f, err := strconv.ParseFloat(v, 64); err == nil {
							scoreGrey = f
						}
					}
				}
			}
		}

		rules := FilterRules{
			BadExtensions:    readFilterLines(extPath),
			BlacklistSenders: readFilterLines(blPath),
			WhitelistSenders: readFilterLines(wlPath),
			BadSubjects:      readFilterLines(subPath),
			ScoreReject:      scoreReject,
			ScoreAddHeader:   scoreHeader,
			ScoreGreylist:    scoreGrey,
		}
		jsonResponse(w, http.StatusOK, rules)

	case "POST":
		var req FilterRules
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
			return
		}

		_ = writeFilterLines(extPath, req.BadExtensions)
		_ = writeFilterLines(blPath, req.BlacklistSenders)
		_ = writeFilterLines(wlPath, req.WhitelistSenders)
		_ = writeFilterLines(subPath, req.BadSubjects)

		if req.ScoreReject <= 0 {
			req.ScoreReject = 15.0
		}
		if req.ScoreAddHeader <= 0 {
			req.ScoreAddHeader = 6.0
		}
		if req.ScoreGreylist <= 0 {
			req.ScoreGreylist = 4.0
		}

		actContent := fmt.Sprintf("reject = %.1f;\nadd_header = %.1f;\ngreylist = %.1f;\n", req.ScoreReject, req.ScoreAddHeader, req.ScoreGreylist)
		_ = os.WriteFile(actPath, []byte(actContent), 0644)

		_ = exec.Command("chown", "-R", "_rspamd:_rspamd", "/etc/rspamd/maps.d", actPath).Run()
		_ = exec.Command("systemctl", "reload", "rspamd").Run()

		jsonResponse(w, http.StatusOK, map[string]string{"message": "Filter rules successfully updated and Rspamd reloaded!"})

	default:
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
	}
}

// --- Email Transaction & Archiving Engine ---

func archiveOldTransactions() (int, error) {
	archiveDir := "/var/log/mail_archives"
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return 0, err
	}

	query := `
		SELECT id, timestamp, COALESCE(message_id, ''), sender, recipient, COALESCE(subject, ''), 
		       status, direction, COALESCE(client_ip, ''), size_bytes, spam_score, COALESCE(details, '')
		FROM email_transactions
		WHERE timestamp < NOW() - INTERVAL '30 days'
		ORDER BY timestamp ASC
	`
	rows, err := db.Query(query)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type archRow struct {
		ID        int       `json:"id"`
		Timestamp time.Time `json:"timestamp"`
		MessageID string    `json:"message_id"`
		Sender    string    `json:"sender"`
		Recipient string    `json:"recipient"`
		Subject   string    `json:"subject"`
		Status    string    `json:"status"`
		Direction string    `json:"direction"`
		ClientIP  string    `json:"client_ip"`
		SizeBytes int64     `json:"size_bytes"`
		SpamScore float64   `json:"spam_score"`
		Details   string    `json:"details"`
	}

	byMonth := make(map[string][]archRow)
	var idsToDelete []int

	for rows.Next() {
		var r archRow
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.MessageID, &r.Sender, &r.Recipient, &r.Subject,
			&r.Status, &r.Direction, &r.ClientIP, &r.SizeBytes, &r.SpamScore, &r.Details); err == nil {
			mKey := r.Timestamp.Format("2006-01")
			byMonth[mKey] = append(byMonth[mKey], r)
			idsToDelete = append(idsToDelete, r.ID)
		}
	}

	if len(idsToDelete) == 0 {
		return 0, nil
	}

	for mKey, items := range byMonth {
		archPath := filepath.Join(archiveDir, fmt.Sprintf("mail_transactions_%s.json.gz", mKey))
		var existingData []archRow

		if f, err := os.Open(archPath); err == nil {
			if gr, err := gzip.NewReader(f); err == nil {
				_ = json.NewDecoder(gr).Decode(&existingData)
				gr.Close()
			}
			f.Close()
		}

		allData := append(existingData, items...)
		buf := new(bytes.Buffer)
		gw := gzip.NewWriter(buf)
		if err := json.NewEncoder(gw).Encode(allData); err == nil {
			gw.Close()
			_ = os.WriteFile(archPath, buf.Bytes(), 0644)
		}
	}

	_, err = db.Exec("DELETE FROM email_transactions WHERE timestamp < NOW() - INTERVAL '30 days'")
	return len(idsToDelete), err
}

func getArchivedFiles() []ArchiveFileInfo {
	var list []ArchiveFileInfo
	archiveDir := "/var/log/mail_archives"
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		return list
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json.gz") {
			info, err := e.Info()
			if err == nil {
				sizeKB := fmt.Sprintf("%.1f KB", float64(info.Size())/1024.0)
				if info.Size() > 1024*1024 {
					sizeKB = fmt.Sprintf("%.2f MB", float64(info.Size())/(1024.0*1024.0))
				}
				list = append(list, ArchiveFileInfo{
					Filename: e.Name(),
					SizeKB:   sizeKB,
					ModTime:  info.ModTime().Format("02 Jan 2006 15:04 WIB"),
				})
			}
		}
	}
	return list
}

func syncAllTransactions() {
	go func() {
		client := http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get("http://127.0.0.1:11334/history")
		if err != nil {
			return
		}
		defer resp.Body.Close()

		var res struct {
			Rows []struct {
				UnixTime  int64                  `json:"unix_time"`
				Subject   string                 `json:"subject"`
				MessageID string                 `json:"message-id"`
				Sender    string                 `json:"sender_smtp"`
				SenderM   string                 `json:"sender_mime"`
				RcptS     []string               `json:"rcpt_smtp"`
				RcptM     []string               `json:"rcpt_mime"`
				Size      int64                  `json:"size"`
				Action    string                 `json:"action"`
				Score     float64                `json:"score"`
				IP        string                 `json:"ip"`
				Symbols   map[string]interface{} `json:"symbols"`
			} `json:"rows"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return
		}

		for _, r := range res.Rows {
			sender := r.Sender
			if sender == "" {
				sender = r.SenderM
			}
			if sender == "" {
				sender = "unknown"
			}
			rcpts := r.RcptS
			if len(rcpts) == 0 {
				rcpts = r.RcptM
			}
			rcpt := strings.Join(rcpts, ", ")
			if rcpt == "" {
				rcpt = "unknown"
			}
			subj := r.Subject
			if subj == "" {
				subj = "(Tanpa Judul)"
			}

			status := "DELIVERED"
			switch r.Action {
			case "reject":
				status = "REJECTED"
			case "add header", "rewrite subject":
				status = "SPAM"
			case "greylist":
				status = "GREYLISTED"
			case "soft reject":
				status = "DEFERRED"
			}

			direction := "INBOUND"
			if strings.Contains(sender, "@elsw-studio.my.id") {
				direction = "OUTBOUND"
			}

			symList := []string{}
			for k := range r.Symbols {
				symList = append(symList, k)
			}
			sort.Strings(symList)
			detailsJSON, _ := json.Marshal(map[string]interface{}{
				"action":    r.Action,
				"symbols":   symList,
				"client_ip": r.IP,
			})

			ts := time.Unix(r.UnixTime, 0)

			var exists int
			_ = db.QueryRow("SELECT id FROM email_transactions WHERE message_id = $1 AND sender = $2", r.MessageID, sender).Scan(&exists)
			if exists == 0 {
				_, _ = db.Exec(`
					INSERT INTO email_transactions 
					(timestamp, message_id, sender, recipient, subject, status, direction, client_ip, size_bytes, spam_score, details)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
				`, ts, r.MessageID, sender, rcpt, subj, status, direction, r.IP, r.Size, r.Score, string(detailsJSON))
			}
		}
	}()

	go func() {
		sentEntries, err := filepath.Glob("/var/mail/vhosts/*/*/.Sent/cur/*")
		if err != nil {
			return
		}
		for _, fPath := range sentEntries {
			info, err := os.Stat(fPath)
			if err != nil {
				continue
			}
			parsed := parseMailFile(fPath, filepath.Base(fPath))
			if parsed.From == "" && parsed.To == "" {
				continue
			}

			fData, _ := os.ReadFile(fPath)
			msgID := ""
			for _, line := range strings.Split(string(fData), "\n") {
				lower := strings.ToLower(line)
				if strings.HasPrefix(lower, "message-id:") {
					msgID = strings.Trim(strings.TrimSpace(line[11:]), "<>")
					break
				}
			}
			if msgID == "" {
				msgID = filepath.Base(fPath)
			}

			var exists int
			_ = db.QueryRow("SELECT id FROM email_transactions WHERE message_id = $1", msgID).Scan(&exists)
			if exists == 0 {
				_, _ = db.Exec(`
					INSERT INTO email_transactions 
					(timestamp, message_id, sender, recipient, subject, status, direction, client_ip, size_bytes, spam_score, details)
					VALUES ($1, $2, $3, $4, $5, 'SENT', 'OUTBOUND', '127.0.0.1', $6, 0.0, 'Dikirim melalui EMXS Webmail / Roundcube')
				`, info.ModTime(), msgID, parsed.From, parsed.To, parsed.Subject, info.Size())
			}
		}
	}()
}

func handleTransactions(w http.ResponseWriter, r *http.Request) {
	syncAllTransactions()

	days := 30
	if dStr := r.URL.Query().Get("days"); dStr != "" {
		if d, err := strconv.Atoi(dStr); err == nil && d > 0 && d <= 30 {
			days = d
		}
	}

	status := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status")))
	direction := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("direction")))
	search := strings.TrimSpace(r.URL.Query().Get("search"))

	limit := 100
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 && l <= 500 {
			limit = l
		}
	}

	baseQuery := `
		SELECT id, timestamp, COALESCE(message_id, ''), sender, recipient, COALESCE(subject, ''), 
		       status, direction, COALESCE(client_ip, ''), size_bytes, spam_score, COALESCE(details, '')
		FROM email_transactions
		WHERE timestamp >= NOW() - ($1 || ' days')::INTERVAL
	`
	args := []interface{}{days}
	argIdx := 2

	if status != "" && status != "ALL" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}

	if direction != "" && direction != "ALL" {
		baseQuery += fmt.Sprintf(" AND direction = $%d", argIdx)
		args = append(args, direction)
		argIdx++
	}

	if search != "" {
		baseQuery += fmt.Sprintf(" AND (sender ILIKE $%d OR recipient ILIKE $%d OR subject ILIKE $%d)", argIdx, argIdx, argIdx)
		args = append(args, "%"+search+"%")
		argIdx++
	}

	baseQuery += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d", argIdx)
	args = append(args, limit)

	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		jsonResponse(w, http.StatusOK, []EmailTransaction{})
		return
	}
	defer rows.Close()

	transactions := []EmailTransaction{}
	for rows.Next() {
		var t EmailTransaction
		var ts time.Time
		if err := rows.Scan(&t.ID, &ts, &t.MessageID, &t.Sender, &t.Recipient, &t.Subject,
			&t.Status, &t.Direction, &t.ClientIP, &t.SizeBytes, &t.SpamScore, &t.Details); err == nil {
			t.Timestamp = ts.Format("2006-01-02 15:04:05")
			transactions = append(transactions, t)
		}
	}

	jsonResponse(w, http.StatusOK, transactions)
}

func handleTransactionStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var totalMonth, totalDelivered, totalSent, totalRejected, totalSpam int
	_ = db.QueryRowContext(ctx, "SELECT count(*) FROM email_transactions WHERE timestamp >= NOW() - INTERVAL '30 days'").Scan(&totalMonth)
	_ = db.QueryRowContext(ctx, "SELECT count(*) FROM email_transactions WHERE timestamp >= NOW() - INTERVAL '30 days' AND status = 'DELIVERED'").Scan(&totalDelivered)
	_ = db.QueryRowContext(ctx, "SELECT count(*) FROM email_transactions WHERE timestamp >= NOW() - INTERVAL '30 days' AND status = 'SENT'").Scan(&totalSent)
	_ = db.QueryRowContext(ctx, "SELECT count(*) FROM email_transactions WHERE timestamp >= NOW() - INTERVAL '30 days' AND status = 'REJECTED'").Scan(&totalRejected)
	_ = db.QueryRowContext(ctx, "SELECT count(*) FROM email_transactions WHERE timestamp >= NOW() - INTERVAL '30 days' AND status = 'SPAM'").Scan(&totalSpam)

	archives := getArchivedFiles()
	var totalArchBytes int64
	for _, a := range archives {
		if info, err := os.Stat(filepath.Join("/var/log/mail_archives", a.Filename)); err == nil {
			totalArchBytes += info.Size()
		}
	}

	stats := TransactionStats{
		TotalMonth:       totalMonth,
		TotalDelivered:   totalDelivered,
		TotalSent:        totalSent,
		TotalRejected:    totalRejected,
		TotalSpam:        totalSpam,
		ArchivedFiles:    len(archives),
		ArchivedBytes:    totalArchBytes,
		MaxRetentionDays: 30,
		ArchivesList:     archives,
	}

	jsonResponse(w, http.StatusOK, stats)
}

func handleManualArchive(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	count, err := archiveOldTransactions()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	msg := fmt.Sprintf("Proses arsip selesai. %d transaksi yang berusia lebih dari 30 hari telah dikompresi ke /var/log/mail_archives/ dan dihapus dari database aktif.", count)
	if count == 0 {
		msg = "Seluruh log saat ini masih berada dalam batas retensi 30 hari (belum ada transaksi > 1 bulan yang perlu diarsip)."
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"archived_count": count,
		"message":        msg,
	})
}

// Webmail Send Implementation
func handleWebmailSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	var req struct {
		From    string `json:"from"`
		To      string `json:"to"`
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.From == "" || req.To == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing From or To address"})
		return
	}

	// Send via local Postfix SMTP on port 25
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		req.From, req.To, req.Subject, time.Now().Format(time.RFC1123Z), req.Body)

	c, err := smtp.Dial("127.0.0.1:25")
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to connect to local MTA: " + err.Error()})
		return
	}
	defer c.Close()

	if err := c.Mail(req.From); err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "MAIL FROM rejected: " + err.Error()})
		return
	}
	if err := c.Rcpt(req.To); err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "RCPT TO rejected: " + err.Error()})
		return
	}
	wc, err := c.Data()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "DATA command rejected: " + err.Error()})
		return
	}
	_, err = wc.Write([]byte(msg))
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to write body: " + err.Error()})
		return
	}
	if err := wc.Close(); err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "Data close error: " + err.Error()})
		return
	}

	// Record in email_transactions
	_, _ = db.Exec(`
		INSERT INTO email_transactions 
		(timestamp, message_id, sender, recipient, subject, status, direction, client_ip, size_bytes, spam_score, details)
		VALUES (NOW(), $1, $2, $3, $4, 'SENT', 'OUTBOUND', $5, $6, 0.0, 'Dispatched via EMXS Console')
	`, fmt.Sprintf("out-%d@elsw-studio.my.id", time.Now().UnixNano()), req.From, req.To, req.Subject, r.RemoteAddr, len(msg))

	jsonResponse(w, http.StatusOK, map[string]string{"message": "Email successfully dispatched to Postfix queue!"})
}

// Webmail Inbox Reader from Maildir
func handleWebmailInbox(w http.ResponseWriter, r *http.Request) {
	email := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))
	if email == "" || !strings.Contains(email, "@") {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Valid email query parameter required"})
		return
	}

	parts := strings.Split(email, "@")
	user := parts[0]
	domain := parts[1]

	baseDir := filepath.Join("/var/mail/vhosts", domain, user)
	messages := []MailMessage{}

	for _, folder := range []string{"new", "cur"} {
		fPath := filepath.Join(baseDir, folder)
		entries, err := os.ReadDir(fPath)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			filePath := filepath.Join(fPath, e.Name())
			msg := parseMailFile(filePath, e.Name())
			messages = append(messages, msg)
		}
	}

	// Sort by date descending
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Date > messages[j].Date
	})

	jsonResponse(w, http.StatusOK, messages)
}

func decodeMimeHeader(val string) string {
	dec := new(mime.WordDecoder)
	if res, err := dec.DecodeHeader(val); err == nil {
		return res
	}
	return val
}

func parseMailFile(path string, filename string) MailMessage {
	msg := MailMessage{Filename: filename, ID: filename}
	data, err := os.ReadFile(path)
	if err != nil {
		return msg
	}

	reader := bytes.NewReader(data)
	parsedMsg, err := mail.ReadMessage(reader)
	if err == nil {
		msg.From = decodeMimeHeader(parsedMsg.Header.Get("From"))
		msg.To = decodeMimeHeader(parsedMsg.Header.Get("To"))
		msg.Subject = decodeMimeHeader(parsedMsg.Header.Get("Subject"))
		msg.Date = parsedMsg.Header.Get("Date")

		contentType := parsedMsg.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "text/plain"
		}
		mediaType, params, err := mime.ParseMediaType(contentType)
		if err == nil && strings.HasPrefix(mediaType, "multipart/") {
			mr := multipart.NewReader(parsedMsg.Body, params["boundary"])
			for {
				p, err := mr.NextPart()
				if err != nil {
					break
				}
				pType, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
				if pType == "text/plain" {
					var bodyBytes []byte
					cte := strings.ToLower(p.Header.Get("Content-Transfer-Encoding"))
					if cte == "quoted-printable" {
						bodyBytes, _ = io.ReadAll(quotedprintable.NewReader(p))
					} else if cte == "base64" {
						bodyBytes, _ = io.ReadAll(base64.NewDecoder(base64.StdEncoding, p))
					} else {
						bodyBytes, _ = io.ReadAll(p)
					}
					msg.Body = string(bodyBytes)
					break
				}
			}
		}
		if msg.Body == "" {
			bodyBytes, _ := io.ReadAll(parsedMsg.Body)
			msg.Body = string(bodyBytes)
		}
	} else {
		// Fallback simple line scan if header parsing fails
		scanner := bufio.NewScanner(bytes.NewReader(data))
		isHeader := true
		var bodyBuf bytes.Buffer
		for scanner.Scan() {
			line := scanner.Text()
			if isHeader {
				if line == "" {
					isHeader = false
					continue
				}
				lower := strings.ToLower(line)
				if strings.HasPrefix(lower, "from:") {
					msg.From = decodeMimeHeader(strings.TrimSpace(line[5:]))
				} else if strings.HasPrefix(lower, "to:") {
					msg.To = decodeMimeHeader(strings.TrimSpace(line[3:]))
				} else if strings.HasPrefix(lower, "subject:") {
					msg.Subject = decodeMimeHeader(strings.TrimSpace(line[8:]))
				} else if strings.HasPrefix(lower, "date:") {
					msg.Date = strings.TrimSpace(line[5:])
				}
			} else {
				bodyBuf.WriteString(line + "\n")
			}
		}
		msg.Body = bodyBuf.String()
	}

	clean := strings.TrimSpace(msg.Body)
	if len(clean) > 120 {
		msg.Snippet = clean[:120] + "..."
	} else {
		msg.Snippet = clean
	}
	return msg
}

func handleWebmailRead(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	filename := r.URL.Query().Get("file")

	if unescaped, err := url.QueryUnescape(email); err == nil {
		email = unescaped
	}
	if unescaped, err := url.QueryUnescape(filename); err == nil {
		filename = unescaped
	}

	if email == "" || filename == "" || !strings.Contains(email, "@") {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing params"})
		return
	}

	parts := strings.Split(email, "@")
	baseDir := filepath.Join("/var/mail/vhosts", parts[1], parts[0])

	// 1. Exact match in new and cur
	for _, folder := range []string{"new", "cur"} {
		path := filepath.Join(baseDir, folder, filename)
		if _, err := os.Stat(path); err == nil {
			parsed := parseMailFile(path, filename)
			data, _ := os.ReadFile(path)
			jsonResponse(w, http.StatusOK, map[string]interface{}{
				"raw":     string(data),
				"body":    parsed.Body,
				"from":    parsed.From,
				"to":      parsed.To,
				"subject": parsed.Subject,
				"date":    parsed.Date,
			})
			return
		}
	}

	// 2. Prefix match (in case Dovecot appended flags :2,S)
	prefix := strings.Split(filename, ":")[0]
	for _, folder := range []string{"new", "cur"} {
		fPath := filepath.Join(baseDir, folder)
		if entries, err := os.ReadDir(fPath); err == nil {
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), prefix) {
					path := filepath.Join(fPath, e.Name())
					parsed := parseMailFile(path, e.Name())
					data, _ := os.ReadFile(path)
					jsonResponse(w, http.StatusOK, map[string]interface{}{
						"raw":     string(data),
						"body":    parsed.Body,
						"from":    parsed.From,
						"to":      parsed.To,
						"subject": parsed.Subject,
						"date":    parsed.Date,
					})
					return
				}
			}
		}
	}

	jsonResponse(w, http.StatusNotFound, map[string]string{"error": "Message file not found"})
}


// ==================== DASHBOARD AUTHENTICATION & TOTP (RFC 6238) ====================

func generateRandomBase32(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func getTOTPCodeAtTime(secret string, t time.Time) (string, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return "", err
		}
	}

	interval := t.Unix() / 30
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(interval))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(hash[offset : offset+4]) & 0x7fffffff
	code := binaryCode % 1000000

	return fmt.Sprintf("%06d", code), nil
}

func validateTOTP(secret string, userCode string) bool {
	userCode = strings.TrimSpace(userCode)
	if len(userCode) != 6 {
		return false
	}
	now := time.Now()
	for _, delta := range []int{-30, 0, 30} {
		calc, err := getTOTPCodeAtTime(secret, now.Add(time.Duration(delta)*time.Second))
		if err == nil && calc == userCode {
			return true
		}
	}
	return false
}

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func createSession(userID int, ip, userAgent string) (string, time.Time, error) {
	token := generateSessionToken()
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err := db.Exec(`
		INSERT INTO dashboard_sessions (token, user_id, ip_address, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, token, userID, ip, userAgent, expiresAt)
	return token, expiresAt, err
}

func deleteSession(token string) error {
	_, err := db.Exec("DELETE FROM dashboard_sessions WHERE token = $1", token)
	return err
}

func cleanupExpiredSessions() {
	_, _ = db.Exec("DELETE FROM dashboard_sessions WHERE expires_at < NOW()")
}

func getUserFromSession(r *http.Request) *DashboardUser {
	cookie, err := r.Cookie("emxs_session")
	if err != nil || cookie.Value == "" {
		return nil
	}
	token := cookie.Value
	var u DashboardUser
	var lastLogin sql.NullTime
	var otpSecret sql.NullString
	err = db.QueryRow(`
		SELECT u.id, u.username, u.email, u.password_hash, u.role, u.otp_enabled, COALESCE(u.otp_secret, ''), u.created_at, u.updated_at, u.last_login
		FROM dashboard_sessions s
		JOIN dashboard_users u ON s.user_id = u.id
		WHERE s.token = $1 AND s.expires_at > NOW()
	`, token).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role, &u.OTPEnabled, &otpSecret, &u.CreatedAt, &u.UpdatedAt, &lastLogin)
	if err != nil {
		return nil
	}
	if otpSecret.Valid {
		u.OTPSecret = otpSecret.String
	}
	if lastLogin.Valid {
		u.LastLogin = &lastLogin.Time
	}
	return &u
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromSession(r)
		if user == nil {
			jsonResponse(w, http.StatusUnauthorized, map[string]string{
				"error": "Sesi tidak valid atau telah berakhir. Silakan login kembali.",
			})
			return
		}
		next(w, r)
	}
}

func initDashboardDB() error {
	createUsersTable := `
	CREATE TABLE IF NOT EXISTS dashboard_users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(50) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		role VARCHAR(50) NOT NULL DEFAULT 'admin',
		otp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
		otp_secret VARCHAR(64),
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_login TIMESTAMPTZ
	);`
	if _, err := db.Exec(createUsersTable); err != nil {
		return fmt.Errorf("create dashboard_users: %w", err)
	}

	createSessionsTable := `
	CREATE TABLE IF NOT EXISTS dashboard_sessions (
		id SERIAL PRIMARY KEY,
		token VARCHAR(128) UNIQUE NOT NULL,
		user_id INTEGER NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
		ip_address VARCHAR(64),
		user_agent TEXT,
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);`
	if _, err := db.Exec(createSessionsTable); err != nil {
		return fmt.Errorf("create dashboard_sessions: %w", err)
	}

	db.Exec(`CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_token ON dashboard_sessions(token);`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_expires ON dashboard_sessions(expires_at);`)

	createTransTable := `
	CREATE TABLE IF NOT EXISTS email_transactions (
		id SERIAL PRIMARY KEY,
		timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		message_id VARCHAR(255),
		sender VARCHAR(255) NOT NULL,
		recipient VARCHAR(255) NOT NULL,
		subject TEXT,
		status VARCHAR(50) NOT NULL,
		direction VARCHAR(20) NOT NULL,
		client_ip VARCHAR(64),
		size_bytes BIGINT DEFAULT 0,
		spam_score NUMERIC(5,2) DEFAULT 0.0,
		details TEXT,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_email_trans_ts ON email_transactions(timestamp);
	CREATE INDEX IF NOT EXISTS idx_email_trans_msgid ON email_transactions(message_id);
	CREATE INDEX IF NOT EXISTS idx_email_trans_sender ON email_transactions(sender);
	CREATE INDEX IF NOT EXISTS idx_email_trans_recipient ON email_transactions(recipient);
	CREATE INDEX IF NOT EXISTS idx_email_trans_status ON email_transactions(status);
	`
	if _, err := db.Exec(createTransTable); err != nil {
		log.Printf("[DB Init] Notice: email_transactions init: %v", err)
	}

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM dashboard_users").Scan(&count)
	if err == nil && count == 0 {
		adminUser := os.Getenv("EMXS_ADMIN_USER")
		if adminUser == "" {
			adminUser = "admin"
		}
		adminEmail := os.Getenv("EMXS_ADMIN_EMAIL")
		if adminEmail == "" {
			adminEmail = "admin@" + configuredDomain
		}
		adminPass := os.Getenv("EMXS_ADMIN_PASS")
		if adminPass == "" {
			adminPass = "Admin_EMXS2026!Sec"
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
		if err == nil {
			secret, _ := generateRandomBase32(20)
			_, err = db.Exec(`
				INSERT INTO dashboard_users (username, email, password_hash, role, otp_enabled, otp_secret)
				VALUES ($1, $2, $3, $4, FALSE, $5)
			`, adminUser, adminEmail, string(hash), "superadmin", secret)
			if err == nil {
				log.Printf("[Dashboard Auth] Default superadmin initialized: %s / %s (email: %s, OTP: disabled)", adminUser, adminPass, adminEmail)
			} else {
				log.Printf("[Dashboard Auth] Failed to insert initial superadmin: %v", err)
			}
		}
	}
	return nil
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		OTPCode  string `json:"otp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Format data tidak valid"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)
	req.OTPCode = strings.TrimSpace(req.OTPCode)

	if req.Username == "" || req.Password == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Username dan kata sandi wajib diisi"})
		return
	}

	var u DashboardUser
	var otpSecret sql.NullString
	var lastLogin sql.NullTime
	err := db.QueryRow(`
		SELECT id, username, email, password_hash, role, otp_enabled, otp_secret, created_at, updated_at, last_login
		FROM dashboard_users
		WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($1)
	`, req.Username).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role, &u.OTPEnabled, &otpSecret, &u.CreatedAt, &u.UpdatedAt, &lastLogin)

	if err != nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "Username atau kata sandi salah"})
		return
	}

	if otpSecret.Valid {
		u.OTPSecret = otpSecret.String
	}
	if lastLogin.Valid {
		u.LastLogin = &lastLogin.Time
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "Username atau kata sandi salah"})
		return
	}

	// If OTP is enabled for this user:
	if u.OTPEnabled {
		if req.OTPCode == "" {
			jsonResponse(w, http.StatusOK, map[string]interface{}{
				"otp_required": true,
				"message":      "Akun ini mengaktifkan Autentikasi Dua Langkah. Masukkan 6 digit kode OTP.",
			})
			return
		}

		if !validateTOTP(u.OTPSecret, req.OTPCode) {
			jsonResponse(w, http.StatusUnauthorized, map[string]string{
				"error": "Kode OTP tidak valid atau telah kadaluarsa. Pastikan jam perangkat Anda akurat.",
			})
			return
		}
	}

	// Login successful: create session
	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = fwd
	}
	userAgent := r.UserAgent()

	token, expiresAt, err := createSession(u.ID, ip, userAgent)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "Gagal membuat sesi login"})
		return
	}

	db.Exec("UPDATE dashboard_users SET last_login = NOW() WHERE id = $1", u.ID)

	http.SetCookie(w, &http.Cookie{
		Name:     "emxs_session",
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"user": map[string]interface{}{
			"id":          u.ID,
			"username":    u.Username,
			"email":       u.Email,
			"role":        u.Role,
			"otp_enabled": u.OTPEnabled,
		},
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("emxs_session")
	if err == nil && cookie.Value != "" {
		deleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "emxs_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	jsonResponse(w, http.StatusOK, map[string]bool{"success": true})
}

func handleAuthMe(w http.ResponseWriter, r *http.Request) {
	user := getUserFromSession(r)
	if user == nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"user": map[string]interface{}{
			"id":          user.ID,
			"username":    user.Username,
			"email":       user.Email,
			"role":        user.Role,
			"otp_enabled": user.OTPEnabled,
		},
	})
}

func handleOTPSetup(w http.ResponseWriter, r *http.Request) {
	user := getUserFromSession(r)
	if user == nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	targetUserID := user.ID
	if uidStr := r.URL.Query().Get("user_id"); uidStr != "" {
		if user.Role == "superadmin" {
			if parsed, err := strconv.Atoi(uidStr); err == nil && parsed > 0 {
				targetUserID = parsed
			}
		}
	}

	var username, email, currentSecret string
	var otpEnabled bool
	err := db.QueryRow(`
		SELECT username, email, COALESCE(otp_secret, ''), otp_enabled 
		FROM dashboard_users WHERE id = $1
	`, targetUserID).Scan(&username, &email, &currentSecret, &otpEnabled)
	if err != nil {
		jsonResponse(w, http.StatusNotFound, map[string]string{"error": "Pengguna tidak ditemukan"})
		return
	}

	if currentSecret == "" {
		currentSecret, _ = generateRandomBase32(20)
		db.Exec("UPDATE dashboard_users SET otp_secret = $1 WHERE id = $2", currentSecret, targetUserID)
	}

	otpauthURL := fmt.Sprintf("otpauth://totp/EMXS:%s?secret=%s&issuer=EMXS%%20Studio", url.PathEscape(username), currentSecret)

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"user_id":     targetUserID,
		"username":    username,
		"otp_enabled": otpEnabled,
		"secret":      currentSecret,
		"otpauth_url": otpauthURL,
	})
}

func handleOTPToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := getUserFromSession(r)
	if user == nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	var req struct {
		UserID int    `json:"user_id"`
		Enable bool   `json:"enable"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Format request tidak valid"})
		return
	}

	targetUserID := user.ID
	if req.UserID > 0 && user.Role == "superadmin" {
		targetUserID = req.UserID
	}

	var secret string
	err := db.QueryRow("SELECT COALESCE(otp_secret, '') FROM dashboard_users WHERE id = $1", targetUserID).Scan(&secret)
	if err != nil {
		jsonResponse(w, http.StatusNotFound, map[string]string{"error": "Pengguna tidak ditemukan"})
		return
	}

	if req.Enable {
		req.Code = strings.TrimSpace(req.Code)
		if req.Code == "" || len(req.Code) != 6 {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Masukkan 6 digit kode OTP untuk konfirmasi aktivasi"})
			return
		}
		if !validateTOTP(secret, req.Code) {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Kode OTP salah. Pastikan Anda memasukkan kode dari aplikasi Authenticator dengan benar."})
			return
		}
		_, err = db.Exec("UPDATE dashboard_users SET otp_enabled = TRUE, updated_at = NOW() WHERE id = $1", targetUserID)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "Gagal mengaktifkan OTP"})
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{"success": true, "otp_enabled": true, "message": "OTP/2FA berhasil diaktifkan!"})
	} else {
		_, err = db.Exec("UPDATE dashboard_users SET otp_enabled = FALSE, updated_at = NOW() WHERE id = $1", targetUserID)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "Gagal menonaktifkan OTP"})
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{"success": true, "otp_enabled": false, "message": "OTP/2FA berhasil dinonaktifkan."})
	}
}

func handleDashboardUsers(w http.ResponseWriter, r *http.Request) {
	user := getUserFromSession(r)
	if user == nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		rows, err := db.Query(`
			SELECT id, username, email, role, otp_enabled, created_at, updated_at, last_login
			FROM dashboard_users
			ORDER BY id ASC
		`)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "Gagal mengambil daftar pengguna"})
			return
		}
		defer rows.Close()

		var users []DashboardUser
		for rows.Next() {
			var u DashboardUser
			var lastLogin sql.NullTime
			if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.OTPEnabled, &u.CreatedAt, &u.UpdatedAt, &lastLogin); err != nil {
				continue
			}
			if lastLogin.Valid {
				u.LastLogin = &lastLogin.Time
			}
			users = append(users, u)
		}

		var activeSessions int
		db.QueryRow("SELECT COUNT(*) FROM dashboard_sessions WHERE expires_at > NOW()").Scan(&activeSessions)

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"users":           users,
			"active_sessions": activeSessions,
			"current_user_id": user.ID,
		})

	case http.MethodPost:
		if user.Role != "superadmin" {
			jsonResponse(w, http.StatusForbidden, map[string]string{"error": "Hanya Superadmin yang dapat menambahkan admin baru"})
			return
		}

		var req struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Format request tidak valid"})
			return
		}

		req.Username = strings.TrimSpace(req.Username)
		req.Email = strings.TrimSpace(req.Email)
		req.Password = strings.TrimSpace(req.Password)
		req.Role = strings.TrimSpace(req.Role)

		if req.Username == "" || req.Email == "" || req.Password == "" {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Username, email, dan kata sandi wajib diisi"})
			return
		}
		if req.Role != "admin" && req.Role != "superadmin" {
			req.Role = "admin"
		}
		if len(req.Password) < 6 {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Kata sandi minimal 6 karakter"})
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "Gagal mengenkripsi kata sandi"})
			return
		}

		secret, _ := generateRandomBase32(20)
		var newID int
		err = db.QueryRow(`
			INSERT INTO dashboard_users (username, email, password_hash, role, otp_enabled, otp_secret)
			VALUES ($1, $2, $3, $4, FALSE, $5)
			RETURNING id
		`, req.Username, req.Email, string(hash), req.Role, secret).Scan(&newID)

		if err != nil {
			if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
				jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Username atau email sudah digunakan"})
				return
			}
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "Gagal membuat pengguna: " + err.Error()})
			return
		}

		jsonResponse(w, http.StatusCreated, map[string]interface{}{
			"success": true,
			"id":      newID,
			"message": "Administrator baru berhasil dibuat (OTP default nonaktif)",
		})

	case http.MethodDelete:
		if user.Role != "superadmin" {
			jsonResponse(w, http.StatusForbidden, map[string]string{"error": "Hanya Superadmin yang dapat menghapus admin"})
			return
		}

		idStr := r.URL.Query().Get("id")
		targetID, err := strconv.Atoi(idStr)
		if err != nil || targetID <= 0 {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "ID pengguna tidak valid"})
			return
		}

		if targetID == user.ID {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Anda tidak dapat menghapus akun Anda sendiri saat sedang aktif"})
			return
		}

		_, err = db.Exec("DELETE FROM dashboard_users WHERE id = $1", targetID)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "Gagal menghapus pengguna"})
			return
		}

		jsonResponse(w, http.StatusOK, map[string]bool{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleUserPasswordReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := getUserFromSession(r)
	if user == nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	var req struct {
		UserID   int    `json:"user_id"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Format request tidak valid"})
		return
	}

	if req.UserID <= 0 {
		req.UserID = user.ID
	} else if req.UserID != user.ID && user.Role != "superadmin" {
		jsonResponse(w, http.StatusForbidden, map[string]string{"error": "Hanya Superadmin yang dapat mereset sandi pengguna lain"})
		return
	}

	req.Password = strings.TrimSpace(req.Password)
	if len(req.Password) < 6 {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Kata sandi minimal 6 karakter"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "Gagal memproses kata sandi"})
		return
	}

	_, err = db.Exec("UPDATE dashboard_users SET password_hash = $1, updated_at = NOW() WHERE id = $2", string(hash), req.UserID)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "Gagal mereset kata sandi"})
		return
	}

	if req.UserID == user.ID {
		cookie, _ := r.Cookie("emxs_session")
		if cookie != nil && cookie.Value != "" {
			db.Exec("DELETE FROM dashboard_sessions WHERE user_id = $1 AND token != $2", req.UserID, cookie.Value)
		}
	} else {
		db.Exec("DELETE FROM dashboard_sessions WHERE user_id = $1", req.UserID)
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{"success": true, "message": "Kata sandi berhasil diperbarui!"})
}

func renderLoginPage(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Masuk — EMXS Studio</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="shortcut icon" href="/favicon.ico">
    <meta name="theme-color" content="#2563eb">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        :root {
            --bg-color: #f8fafc;
            --card-bg: #ffffff;
            --card-border: #e2e8f0;
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --primary-glow: rgba(37, 99, 235, 0.2);
            --text-title: #0f172a;
            --text-body: #64748b;
            --input-bg: #f8fafc;
            --input-border: #cbd5e1;
            --input-focus: #2563eb;
            --error-bg: #fef2f2;
            --error-border: #fecaca;
            --error-text: #b91c1c;
            --success-bg: #f0fdf4;
            --success-border: #bbf7d0;
            --success-text: #15803d;
        }
        body {
            font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(at 0% 0%, rgba(37, 99, 235, 0.08) 0, transparent 50%),
                radial-gradient(at 100% 100%, rgba(99, 102, 241, 0.08) 0, transparent 50%),
                radial-gradient(at 50% 50%, rgba(241, 245, 249, 0.6) 0, transparent 100%);
            color: var(--text-title);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 24px 16px;
        }
        .login-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 20px;
            box-shadow: 0 20px 40px -15px rgba(15, 23, 42, 0.08), 0 1px 3px 0 rgba(0, 0, 0, 0.05);
            width: 100%;
            max-width: 420px;
            padding: 38px 32px;
            position: relative;
            overflow: hidden;
        }
        .login-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 3px;
            background: linear-gradient(90deg, #2563eb, #3b82f6, #6366f1);
        }
        .brand-header {
            text-align: center;
            margin-bottom: 28px;
        }
        .brand-logo-wrap {
            width: 56px;
            height: 56px;
            margin: 0 auto 14px;
            border-radius: 16px;
            background: linear-gradient(135deg, #2563eb, #1d4ed8);
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 8px 20px -4px var(--primary-glow);
        }
        .brand-title {
            font-size: 24px;
            font-weight: 800;
            letter-spacing: -0.5px;
            color: var(--text-title);
            margin-bottom: 4px;
        }
        .brand-subtitle {
            font-size: 13px;
            color: var(--text-body);
            line-height: 1.4;
        }
        .server-badge {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            margin-top: 10px;
            padding: 4px 12px;
            background: #f1f5f9;
            border: 1px solid #e2e8f0;
            border-radius: 9999px;
            font-size: 11.5px;
            color: #475569;
            font-weight: 500;
        }
        .server-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: #10b981;
            box-shadow: 0 0 6px #10b981;
        }
        .alert-box {
            padding: 12px 14px;
            border-radius: 10px;
            font-size: 13px;
            line-height: 1.4;
            margin-bottom: 18px;
            display: none;
            animation: fadeIn 0.3s ease;
        }
        .alert-error {
            background: var(--error-bg);
            border: 1px solid var(--error-border);
            color: var(--error-text);
        }
        .alert-success {
            background: var(--success-bg);
            border: 1px solid var(--success-border);
            color: var(--success-text);
        }
        .form-group {
            margin-bottom: 18px;
        }
        .form-label {
            display: block;
            font-size: 12px;
            font-weight: 600;
            color: #334155;
            margin-bottom: 7px;
            letter-spacing: 0.3px;
        }
        .input-wrap {
            position: relative;
            display: flex;
            align-items: center;
        }
        .input-icon {
            position: absolute;
            left: 13px;
            color: #94a3b8;
            pointer-events: none;
            display: flex;
            align-items: center;
        }
        .form-input {
            width: 100%;
            padding: 11px 14px 11px 40px;
            background: var(--input-bg);
            border: 1px solid var(--input-border);
            border-radius: 10px;
            color: var(--text-title);
            font-size: 14px;
            font-family: inherit;
            transition: all 0.2s ease;
            outline: none;
        }
        .form-input:focus {
            border-color: var(--input-focus);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
            background: #ffffff;
        }
        .btn-eye {
            position: absolute;
            right: 12px;
            background: transparent;
            border: none;
            color: #94a3b8;
            cursor: pointer;
            padding: 4px;
            display: flex;
            align-items: center;
            border-radius: 6px;
            transition: color 0.2s;
        }
        .btn-eye:hover { color: #334155; }
        .btn-primary-login {
            width: 100%;
            padding: 12px 18px;
            background: var(--primary);
            border: none;
            border-radius: 10px;
            color: #ffffff;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            transition: all 0.2s ease;
            box-shadow: 0 4px 14px rgba(37, 99, 235, 0.3);
            margin-top: 8px;
        }
        .btn-primary-login:hover:not(:disabled) {
            background: var(--primary-hover);
            box-shadow: 0 6px 18px rgba(37, 99, 235, 0.4);
        }
        .btn-primary-login:disabled {
            opacity: 0.65;
            cursor: not-allowed;
            transform: none;
        }
        .spin {
            animation: rotate 1s linear infinite;
        }
        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-4px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .otp-banner-box {
            text-align: center;
            padding: 14px;
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            border-radius: 12px;
            margin-bottom: 20px;
        }
        .otp-banner-icon {
            width: 42px;
            height: 42px;
            margin: 0 auto 8px;
            border-radius: 10px;
            background: #dbeafe;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #2563eb;
        }
        .otp-input-code {
            text-align: center;
            font-family: 'JetBrains Mono', monospace;
            font-size: 26px;
            letter-spacing: 12px;
            padding: 12px 10px;
            font-weight: 700;
            color: var(--text-title);
            background: #ffffff;
            border: 2px solid #2563eb;
        }
        .btn-link-back {
            background: none;
            border: none;
            color: #64748b;
            font-size: 13px;
            cursor: pointer;
            margin-top: 16px;
            width: 100%;
            text-align: center;
            transition: color 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }
        .btn-link-back:hover { color: #0f172a; }
        .footer-note {
            text-align: center;
            margin-top: 26px;
            font-size: 11.5px;
            color: #94a3b8;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="brand-header">
            <div class="brand-logo-wrap">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
                    <polyline points="22,6 12,13 2,6"/>
                </svg>
            </div>
            <h1 class="brand-title">EMXS Studio</h1>
            <p class="brand-subtitle">Email Exchanger Management Dashboard</p>
            <div class="server-badge">
                <span class="server-dot"></span>
                mail.elsw-studio.my.id &bull; TLS 1.3 Active
            </div>
        </div>

        <div id="login-alert" class="alert-box"></div>

        <!-- FORM STEP 1: USERNAME & PASSWORD -->
        <form id="form-login" onsubmit="submitLogin(event)">
            <div class="form-group">
                <label class="form-label" for="login-username">USERNAME ATAU EMAIL</label>
                <div class="input-wrap">
                    <span class="input-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    </span>
                    <input type="text" id="login-username" class="form-input" placeholder="admin" required autocomplete="username" autofocus>
                </div>
            </div>

            <div class="form-group">
                <label class="form-label" for="login-password">KATA SANDI</label>
                <div class="input-wrap">
                    <span class="input-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    </span>
                    <input type="password" id="login-password" class="form-input" placeholder="••••••••••••" required autocomplete="current-password" style="padding-right: 44px;">
                    <button type="button" class="btn-eye" onclick="togglePasswordVisibility()" title="Lihat Sandi">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                    </button>
                </div>
            </div>

            <button type="submit" id="btn-submit-login" class="btn-primary-login">
                <span id="btn-login-label">Masuk ke Dashboard</span>
                <svg id="btn-login-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
            </button>
        </form>

        <!-- FORM STEP 2: OTP / 2FA (DYNAMIC TRANSITION) -->
        <form id="form-otp" onsubmit="submitOTP(event)" style="display: none;">
            <div class="otp-banner-box">
                <div class="otp-banner-icon">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                <h3 style="font-size: 15px; font-weight: 700; color: #1e3a8a; margin-bottom: 4px;">Autentikasi Dua Langkah (2FA)</h3>
                <p style="font-size: 12px; color: #2563eb; line-height: 1.4;">Buka aplikasi Authenticator Anda dan masukkan 6 digit kode OTP:</p>
            </div>

            <div class="form-group">
                <label class="form-label" for="login-otp" style="text-align: center;">KODE OTP 6 DIGIT</label>
                <div class="input-wrap">
                    <input type="text" id="login-otp" class="form-input otp-input-code" placeholder="000000" maxlength="6" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code">
                </div>
            </div>

            <button type="submit" id="btn-submit-otp" class="btn-primary-login">
                <span id="btn-otp-label">Verifikasi & Masuk</span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
            </button>

            <button type="button" class="btn-link-back" onclick="backToLoginForm()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
                <span>Kembali ke Form Login</span>
            </button>
        </form>

        <div class="footer-note">
            EMXS Enterprise Edition &bull; TLS 1.3 &bull; Postfix / Dovecot Engine
        </div>
    </div>

    <script>
        var cachedAuth = { username: '', password: '' };

        function togglePasswordVisibility() {
            var pwd = document.getElementById('login-password');
            if (pwd.type === 'password') {
                pwd.type = 'text';
            } else {
                pwd.type = 'password';
            }
        }

        function showAlert(msg, isSuccess) {
            var el = document.getElementById('login-alert');
            el.textContent = msg;
            el.className = 'alert-box ' + (isSuccess ? 'alert-success' : 'alert-error');
            el.style.display = 'block';
        }

        function hideAlert() {
            var el = document.getElementById('login-alert');
            el.style.display = 'none';
        }

        function submitLogin(e) {
            e.preventDefault();
            hideAlert();

            var u = document.getElementById('login-username').value.trim();
            var p = document.getElementById('login-password').value;
            if (!u || !p) {
                showAlert('Username dan kata sandi wajib diisi.', false);
                return;
            }

            cachedAuth.username = u;
            cachedAuth.password = p;

            var btn = document.getElementById('btn-submit-login');
            var label = document.getElementById('btn-login-label');
            var arrow = document.getElementById('btn-login-arrow');
            btn.disabled = true;
            label.textContent = 'Memverifikasi...';
            arrow.innerHTML = '<path class="spin" d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83"/>';

            fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: u, password: p })
            })
            .then(function(res) {
                return res.json().then(function(data) {
                    return { ok: res.ok, status: res.status, data: data };
                });
            })
            .then(function(result) {
                if (!result.ok) {
                    showAlert(result.data.error || 'Username atau password tidak sesuai.', false);
                    btn.disabled = false;
                    label.textContent = 'Masuk ke Dashboard';
                    arrow.innerHTML = '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>';
                    return;
                }

                if (result.data.otp_required) {
                    document.getElementById('form-login').style.display = 'none';
                    document.getElementById('form-otp').style.display = 'block';
                    var otpInp = document.getElementById('login-otp');
                    otpInp.value = '';
                    otpInp.focus();
                    btn.disabled = false;
                    label.textContent = 'Masuk ke Dashboard';
                    arrow.innerHTML = '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>';
                    return;
                }

                showAlert('Login berhasil! Mengalihkan ke dashboard...', true);
                setTimeout(function() {
                    window.location.href = '/';
                }, 400);
            })
            .catch(function(err) {
                showAlert('Gagal terhubung ke server mail-api.', false);
                btn.disabled = false;
                label.textContent = 'Masuk ke Dashboard';
                arrow.innerHTML = '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>';
            });
        }

        function submitOTP(e) {
            e.preventDefault();
            hideAlert();

            var code = document.getElementById('login-otp').value.trim();
            if (!code || code.length !== 6) {
                showAlert('Masukkan 6 digit angka kode OTP.', false);
                return;
            }

            var btn = document.getElementById('btn-submit-otp');
            var label = document.getElementById('btn-otp-label');
            btn.disabled = true;
            label.textContent = 'Memverifikasi OTP...';

            fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: cachedAuth.username,
                    password: cachedAuth.password,
                    otp_code: code
                })
            })
            .then(function(res) {
                return res.json().then(function(data) {
                    return { ok: res.ok, status: res.status, data: data };
                });
            })
            .then(function(result) {
                if (!result.ok) {
                    showAlert(result.data.error || 'Kode OTP salah atau telah kadaluarsa.', false);
                    btn.disabled = false;
                    label.textContent = 'Verifikasi & Masuk';
                    return;
                }

                showAlert('Kode OTP terverifikasi! Membuka dashboard...', true);
                setTimeout(function() {
                    window.location.href = '/';
                }, 400);
            })
            .catch(function(err) {
                showAlert('Gagal terhubung ke server.', false);
                btn.disabled = false;
                label.textContent = 'Verifikasi & Masuk';
            });
        }

        function backToLoginForm() {
            hideAlert();
            document.getElementById('form-otp').style.display = 'none';
            document.getElementById('form-login').style.display = 'block';
            document.getElementById('login-password').focus();
        }
    </script>
</body>
</html>`
	if configuredHost != "mail.elsw-studio.my.id" {
		html = strings.ReplaceAll(html, "mail.elsw-studio.my.id", configuredHost)
	}
	if configuredDomain != "elsw-studio.my.id" {
		html = strings.ReplaceAll(html, "elsw-studio.my.id", configuredDomain)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Write([]byte(html))
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	user := getUserFromSession(r)
	if user == nil {
		renderLoginPage(w, r)
		return
	}

	html := `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EMXS — Email Exchanger Studio</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="shortcut icon" href="/favicon.ico">
    <meta name="theme-color" content="#2563eb">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" media="print" onload="this.media='all'">
    <noscript><link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"></noscript>
    <style>
        :root {
            --bg-page: #f8fafc;
            --bg-sidebar: #ffffff;
            --surface: #ffffff;
            --surface-hover: #f1f5f9;
            --border: #e2e8f0;
            --border-light: #edf2f7;
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --primary-light: #eff6ff;
            --text-title: #0f172a;
            --text-body: #334155;
            --text-muted: #64748b;
            --success: #059669;
            --success-light: #ecfdf5;
            --danger: #dc2626;
            --danger-light: #fef2f2;
            --warning: #d97706;
            --warning-light: #fffbeb;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.07), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.08), 0 4px 6px -4px rgba(0, 0, 0, 0.04);
            --radius-md: 10px;
            --radius-lg: 16px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        body { background: var(--bg-page); color: var(--text-body); display: flex; height: 100vh; overflow: hidden; -webkit-font-smoothing: antialiased; }

        /* Left Sidebar */
        .sidebar { width: 270px; background: var(--bg-sidebar); border-right: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; z-index: 10; }
        .sidebar-brand { padding: 24px 22px; display: flex; align-items: center; gap: 12px; border-bottom: 1px solid var(--border-light); }
        .brand-logo { width: 38px; height: 38px; background: linear-gradient(135deg, #2563eb 0%, #4f46e5 100%); border-radius: 10px; display: flex; align-items: center; justify-content: center; color: #fff; box-shadow: 0 4px 10px rgba(37, 99, 235, 0.25); }
        .brand-title h1 { font-size: 17px; font-weight: 700; color: var(--text-title); letter-spacing: -0.3px; }
        .brand-title p { font-size: 11px; color: var(--text-muted); font-weight: 500; }

        .nav-menu { padding: 18px 12px; flex-grow: 1; overflow-y: auto; list-style: none; }
        .nav-category { font-size: 11px; font-weight: 700; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.6px; padding: 12px 12px 6px 12px; }
        .nav-link { display: flex; align-items: center; gap: 12px; padding: 11px 14px; border-radius: var(--radius-md); color: var(--text-body); font-size: 13.5px; font-weight: 600; cursor: pointer; transition: all 0.15s ease; margin-bottom: 4px; }
        .nav-link:hover { background: var(--surface-hover); color: var(--text-title); }
        .nav-link.active { background: var(--primary-light); color: var(--primary); font-weight: 700; }
        .nav-link svg { width: 19px; height: 19px; stroke-width: 2; flex-shrink: 0; }

        .sidebar-footer { padding: 18px 22px; border-top: 1px solid var(--border-light); background: #fafafa; font-size: 12px; }
        .status-pill { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 20px; font-weight: 600; font-size: 11.5px; background: var(--success-light); color: var(--success); border: 1px solid rgba(5, 150, 105, 0.2); }
        .status-dot { width: 6px; height: 6px; background: var(--success); border-radius: 50%; }

        /* Main Workspace */
        .workspace { flex-grow: 1; display: flex; flex-direction: column; overflow: hidden; background: var(--bg-page); }
        .header { height: 68px; background: var(--surface); border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; padding: 0 32px; flex-shrink: 0; box-shadow: var(--shadow-sm); }
        .header-title h2 { font-size: 19px; font-weight: 700; color: var(--text-title); letter-spacing: -0.4px; }
        .header-actions { display: flex; align-items: center; gap: 12px; }

        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 18px; border-radius: 9px; font-size: 13px; font-weight: 600; border: none; cursor: pointer; transition: all 0.15s ease; text-decoration: none; line-height: 1; }
        .btn svg { flex-shrink: 0; stroke-width: 2.2; }
        .btn-primary { background: #2563eb; color: #fff; box-shadow: 0 2px 6px rgba(37, 99, 235, 0.25); border: 1px solid #1d4ed8; }
        .btn-primary:hover { background: #1d4ed8; transform: translateY(-1px); box-shadow: 0 4px 10px rgba(37, 99, 235, 0.35); }
        .btn-outline { background: #ffffff; color: #334155; border: 1px solid #cbd5e1; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
        .btn-outline:hover { background: #f8fafc; color: #0f172a; border-color: #94a3b8; }
        .btn-danger { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
        .btn-danger:hover { background: #dc2626; color: #fff; border-color: #b91c1c; }
        .btn-sm { padding: 6px 12px; font-size: 12px; border-radius: 7px; gap: 6px; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        .spin { animation: spin 1s linear infinite; }

        .content { flex-grow: 1; overflow-y: auto; padding: 32px; }
        .tab-content { display: none; }
        .tab-content.active { display: block; animation: fadeIn 0.2s ease-out; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

        /* KPI Cards */
        .grid-kpi { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 20px; margin-bottom: 28px; }
        .kpi-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 22px; box-shadow: var(--shadow-sm); transition: all 0.2s; }
        .kpi-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-md); border-color: #cbd5e1; }
        .kpi-header { display: flex; justify-content: space-between; align-items: center; }
        .kpi-label { font-size: 12.5px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
        .kpi-icon { width: 34px; height: 34px; border-radius: 9px; display: flex; align-items: center; justify-content: center; background: var(--primary-light); color: var(--primary); }
        .kpi-val { font-size: 32px; font-weight: 800; color: var(--text-title); margin: 12px 0 4px 0; letter-spacing: -0.5px; }
        .kpi-sub { font-size: 12px; color: var(--text-muted); font-weight: 500; }

        /* Elegant Panels */
        .panel { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 26px; box-shadow: var(--shadow-sm); margin-bottom: 26px; }
        .panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 22px; }
        .panel-header h3 { font-size: 16.5px; font-weight: 700; color: var(--text-title); letter-spacing: -0.2px; }

        /* Modern Tables */
        table { width: 100%; border-collapse: separate; border-spacing: 0; }
        th { text-align: left; padding: 13px 16px; font-size: 11.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); border-bottom: 1px solid var(--border); background: #fafafa; }
        th:first-child { border-top-left-radius: 8px; }
        th:last-child { border-top-right-radius: 8px; }
        td { padding: 15px 16px; font-size: 13.5px; border-bottom: 1px solid var(--border-light); vertical-align: middle; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: #f8fafc; }

        /* Form elements */
        .form-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 18px; margin-bottom: 18px; }
        .form-group { display: flex; flex-direction: column; gap: 6px; }
        label { font-size: 13px; font-weight: 600; color: var(--text-title); }
        input, select, textarea { width: 100%; background: #ffffff; border: 1px solid var(--border); color: var(--text-title); padding: 10px 14px; border-radius: 9px; font-size: 13.5px; outline: none; transition: all 0.15s; }
        input:focus, select:focus, textarea:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12); }

        .tag-status { display: inline-flex; align-items: center; gap: 5px; padding: 3px 9px; border-radius: 6px; font-size: 12px; font-weight: 600; }
        .tag-active { background: var(--success-light); color: var(--success); border: 1px solid rgba(5, 150, 105, 0.2); }
        .tag-inactive { background: var(--danger-light); color: var(--danger); border: 1px solid rgba(220, 38, 38, 0.2); }

        .console-light { background: #0f172a; color: #f1f5f9; border-radius: 12px; padding: 18px; font-family: 'JetBrains Mono', monospace; font-size: 12px; line-height: 1.6; height: 460px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }

        /* Modal */
        .modal { display: none; position: fixed; inset: 0; background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(4px); align-items: center; justify-content: center; padding: 20px; z-index: 999; }
        .modal.active { display: flex !important; }
        .modal-card { background: #ffffff; border-radius: 16px; box-shadow: var(--shadow-lg); max-width: 620px; width: 100%; padding: 28px; border: 1px solid var(--border); }
        .code-snippet { background: #f1f5f9; border: 1px dashed #cbd5e1; border-radius: 8px; padding: 12px; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--primary); margin: 8px 0 16px 0; word-break: break-all; }

        /* Webmail inbox */
        .inbox-item { padding: 14px 18px; border-bottom: 1px solid var(--border-light); cursor: pointer; transition: background 0.15s; display: flex; align-items: center; justify-content: space-between; }
        .inbox-item:hover { background: #f8fafc; }
        .inbox-item.unread { font-weight: 700; background: #fafafa; }
    </style>
</head>
<body>
    <!-- Sidebar Navigation -->
    <div class="sidebar">
        <div class="sidebar-brand">
            <div class="brand-logo">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
            </div>
            <div class="brand-title">
                <h1>EMXS</h1>
                <p>Email Exchanger Studio</p>
            </div>
        </div>

        <ul class="nav-menu">
            <li class="nav-category">Overview</li>
            <li class="nav-link active" onclick="nav('dashboard')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>
                Dashboard
            </li>
            <li class="nav-link" onclick="nav('transactions')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                History
            </li>
            <li class="nav-link" onclick="nav('webmail')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21.2 8.4c.5.38.8.97.8 1.6v10a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V10a2 2 0 0 1 .8-1.6l8-6a2 2 0 0 1 2.4 0l8 6z"/><path d="m22 10-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 10"/></svg>
                Mail Tester Console
            </li>

            <li class="nav-category">Management</li>
            <li class="nav-link" onclick="nav('domains')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                Virtual Domains
            </li>
            <li class="nav-link" onclick="nav('mailboxes')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                Mailbox Accounts
            </li>
            <li class="nav-link" onclick="nav('aliases')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/></svg>
                Aliases & Forwards
            </li>

            <li class="nav-category">Security & Diagnostics</li>
            <li class="nav-link" onclick="nav('deliverability')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                DNS & Deliverability
            </li>
            <li class="nav-link" onclick="nav('filtering')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>
                Content & Spam Filter
            </li>
            <li class="nav-link" onclick="nav('queue')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                Mail Queue Manager
            </li>
            <li class="nav-link" onclick="nav('logs')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                System Logs
            </li>

            <li class="nav-category">Access Control</li>
            <li class="nav-link" onclick="nav('users')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                User Management & 2FA
            </li>
        </ul>

        <div class="sidebar-footer">
            <div class="status-pill">
                <div class="status-dot"></div>
                SSL Let's Encrypt Active
            </div>
        </div>
    </div>

    <!-- Main Workspace -->
    <div class="workspace">
        <div class="header">
            <div class="header-title">
                <h2 id="header-text">System Dashboard</h2>
            </div>
            <div class="header-actions">
                <button class="btn btn-primary btn-sm" onclick="nav('webmail')">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/></svg>
                    <span>Kirim Email Uji</span>
                </button>
                <a href="/webmail/" target="_blank" class="btn btn-outline btn-sm" style="text-decoration: none;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
                    <span>Buka Webmail ↗</span>
                </a>
                <div class="status-pill" style="background:#f1f5f9; color:#334155; border-color:#cbd5e1;">
                    Host: mail.elsw-studio.my.id
                </div>
                <div class="user-profile-badge" style="display:inline-flex; align-items:center; gap:8px; padding:3px 10px 3px 5px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:9999px; margin-left:4px;">
                    <div style="width:28px; height:28px; border-radius:50%; background:linear-gradient(135deg, #2563eb, #7c3aed); color:#fff; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:11px;" id="nav-user-avatar">AD</div>
                    <div style="display:flex; flex-direction:column; line-height:1.2; text-align:left;">
                        <span style="font-size:12px; font-weight:600; color:#0f172a;" id="nav-username">admin</span>
                        <span style="font-size:10px; color:#64748b; font-weight:500;" id="nav-user-role">Superadmin</span>
                    </div>
                    <button onclick="handleLogout()" title="Keluar / Logout" style="border:none; background:transparent; cursor:pointer; color:#ef4444; padding:3px 4px; border-radius:4px; display:inline-flex; align-items:center; margin-left:4px;">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                    </button>
                </div>
            </div>
        </div>

        <div class="content">
            <!-- TAB 1: DASHBOARD -->
            <div id="tab-dashboard" class="tab-content active">
                <div class="grid-kpi">
                    <div class="kpi-card">
                        <div class="kpi-header"><span class="kpi-label">Virtual Domains</span><div class="kpi-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/></svg></div></div>
                        <div class="kpi-val" id="kpi-domains">-</div>
                        <div class="kpi-sub">Multi-tenant ready</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-header"><span class="kpi-label">Mailboxes</span><div class="kpi-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/></svg></div></div>
                        <div class="kpi-val" id="kpi-accounts">-</div>
                        <div class="kpi-sub">PostgreSQL Virtual Users</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-header"><span class="kpi-label">Aliases</span><div class="kpi-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/></svg></div></div>
                        <div class="kpi-val" id="kpi-aliases">-</div>
                        <div class="kpi-sub">Forwarders & Redirects</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-header"><span class="kpi-label">Mail Queue</span><div class="kpi-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div></div>
                        <div class="kpi-val" id="kpi-queue">-</div>
                        <div class="kpi-sub" style="color: var(--success);">0 Pending / Clean</div>
                    </div>
                </div>

                <!-- 30-Day Email Transactions Activity KPIs -->
                <div class="grid-kpi">
                    <div class="kpi-card">
                        <div class="kpi-header">
                            <span class="kpi-label">Total Transaksi (30 Hari)</span>
                            <div class="kpi-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div>
                        </div>
                        <div class="kpi-val" id="kpi-tx-total">0</div>
                        <div class="kpi-sub">Rentang maks. 1 bulan aktif di DB</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-header">
                            <span class="kpi-label">Berhasil Terkirim &amp; Diterima</span>
                            <div class="kpi-icon" style="background: var(--success-light); color: var(--success);"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="20 6 9 17 4 12"/></svg></div>
                        </div>
                        <div class="kpi-val" id="kpi-tx-delivered" style="color: var(--success);">0</div>
                        <div class="kpi-sub" id="kpi-tx-delivered-sub">0 Terkirim | 0 Diterima</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-header">
                            <span class="kpi-label">Spam &amp; Ditolak (Blocked)</span>
                            <div class="kpi-icon" style="background: var(--danger-light); color: var(--danger);"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg></div>
                        </div>
                        <div class="kpi-val" id="kpi-tx-rejected" style="color: var(--danger);">0</div>
                        <div class="kpi-sub" id="kpi-tx-rejected-sub">0 Spam | 0 Rejected</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-header">
                            <span class="kpi-label">File Terarsip (> 30 Hari)</span>
                            <div class="kpi-icon" style="background: #f1f5f9; color: #475569;"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></div>
                        </div>
                        <div class="kpi-val" id="kpi-tx-archives">0 File</div>
                        <div class="kpi-sub" id="kpi-tx-archives-size">0 KB dikompresi (.json.gz)</div>
                    </div>
                </div>

                <!-- Services Health -->
                <div class="panel">
                    <div class="panel-header">
                        <h3>Core Daemon Status</h3>
                        <button class="btn btn-outline btn-sm" onclick="fetchStats()">Refresh</button>
                    </div>
                    <table>
                        <thead><tr><th>Service Name</th><th>Port & Protocols</th><th>Status</th></tr></thead>
                        <tbody id="table-services"><tr><td colspan="3">Loading services...</td></tr></tbody>
                    </table>
                </div>

                <!-- Storage & Uptime -->
                <div class="panel">
                    <div class="panel-header"><h3>Storage & Server Resources</h3></div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                        <div style="background: #f8fafc; border: 1px solid var(--border); padding: 18px; border-radius: 12px;">
                            <div style="font-size: 13px; color: var(--text-muted); font-weight: 600;">Maildir Storage (/var/mail/vhosts)</div>
                            <div style="font-size: 24px; font-weight: 700; color: var(--text-title); margin-top: 6px;" id="val-disk">- Used</div>
                        </div>
                        <div style="background: #f8fafc; border: 1px solid var(--border); padding: 18px; border-radius: 12px;">
                            <div style="font-size: 13px; color: var(--text-muted); font-weight: 600;">System Uptime</div>
                            <div style="font-size: 24px; font-weight: 700; color: var(--text-title); margin-top: 6px;" id="val-uptime">-</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TAB 2: WEBMAIL TESTER -->
            <div id="tab-webmail" class="tab-content">
                <div style="display: grid; grid-template-columns: 1.1fr 0.9fr; gap: 24px;">
                    <!-- Compose Email -->
                    <div class="panel">
                        <div class="panel-header">
                            <h3>✉️ Compose & Send Test Email</h3>
                        </div>
                        <form onsubmit="sendTestEmail(event)">
                            <div class="form-group" style="margin-bottom: 14px;">
                                <label>From (Pengirim)</label>
                                <input type="email" id="wm-from" placeholder="admin@elsw-studio.my.id" required>
                            </div>
                            <div class="form-group" style="margin-bottom: 14px;">
                                <label>To (Penerima)</label>
                                <input type="email" id="wm-to" placeholder="tujuan@gmail.com" required>
                            </div>
                            <div class="form-group" style="margin-bottom: 14px;">
                                <label>Subject</label>
                                <input type="text" id="wm-subj" value="Test Email from Native Server" required>
                            </div>
                            <div class="form-group" style="margin-bottom: 18px;">
                                <label>Message Body</label>
                                <textarea id="wm-body" rows="6" placeholder="Ketik pesan email kamu di sini..." required>Halo! Ini adalah email uji coba dari mail server native (Postfix + Dovecot + Rspamd DKIM).</textarea>
                            </div>
                            <button type="submit" class="btn btn-primary" style="width: 100%; padding: 12px; font-size: 14px; gap: 10px;">
                                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/></svg>
                                <span>Kirim Email Sekarang</span>
                            </button>
                        </form>
                    </div>

                    <!-- View Mailbox Inbox -->
                    <div class="panel">
                        <div class="panel-header">
                            <h3>📬 Inbox Reader (Maildir)</h3>
                            <button class="btn btn-outline btn-sm" onclick="fetchInbox()">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
                                <span>Segarkan Inbox</span>
                            </button>
                        </div>
                        <div class="form-group" style="margin-bottom: 16px;">
                            <label>Pilih Mailbox untuk Dibaca</label>
                            <select id="wm-inbox-email" onchange="fetchInbox()"></select>
                        </div>
                        <div id="inbox-list" style="border: 1px solid var(--border); border-radius: 10px; max-height: 380px; overflow-y: auto;">
                            <div style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 13px;">Pilih akun mailbox di atas untuk melihat isi kotak masuk.</div>
                        </div>
                    </div>
                </div>

                <!-- Client Connection Guide -->
                <div class="panel">
                    <div class="panel-header"><h3>Client Configuration (Thunderbird / Outlook / Apple Mail / Android)</h3></div>
                    <table style="max-width: 800px;">
                        <tr><td style="width: 220px; font-weight: 600;">Incoming (IMAP)</td><td><code>mail.elsw-studio.my.id</code> | Port <strong>993</strong> (SSL/TLS)</td></tr>
                        <tr><td style="font-weight: 600;">Outgoing (SMTP Submission)</td><td><code>mail.elsw-studio.my.id</code> | Port <strong>465</strong> (SSL) atau <strong>587</strong> (STARTTLS)</td></tr>
                        <tr><td style="font-weight: 600;">Username</td><td>Alamat email lengkap (contoh: <code>admin@elsw-studio.my.id</code>)</td></tr>
                        <tr><td style="font-weight: 600;">Password</td><td>Password mailbox yang dibuat di menu Accounts</td></tr>
                    </table>
                </div>
            </div>

            <!-- TAB 3: DOMAINS -->
            <div id="tab-domains" class="tab-content">
                <div class="panel">
                    <div class="panel-header"><h3>Add Virtual Domain</h3></div>
                    <form onsubmit="addDomain(event)">
                        <div class="form-row">
                            <div class="form-group" style="grid-column: span 2;">
                                <label>Domain Name</label>
                                <input type="text" id="dom-name" placeholder="example.com" required>
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
                        <span>Tambah Domain & Generate DKIM</span>
                    </button>
                    </form>
                </div>

                <div class="panel">
                    <div class="panel-header">
                        <h3>Configured Domains</h3>
                        <button class="btn btn-outline btn-sm" onclick="fetchDomains()">Refresh</button>
                    </div>
                    <table>
                        <thead><tr><th>ID</th><th>Domain Name</th><th>Mailboxes</th><th>Status</th><th>Actions</th></tr></thead>
                        <tbody id="table-domains"><tr><td colspan="5">Loading domains...</td></tr></tbody>
                    </table>
                </div>
            </div>

            <!-- TAB 4: MAILBOXES -->
            <div id="tab-mailboxes" class="tab-content">
                <div class="panel">
                    <div class="panel-header"><h3>Create New Mailbox</h3></div>
                    <form onsubmit="addAccount(event)">
                        <div class="form-row">
                            <div class="form-group">
                                <label>Domain</label>
                                <select id="acc-domain" required></select>
                            </div>
                            <div class="form-group">
                                <label>Username (Local Part)</label>
                                <input type="text" id="acc-user" placeholder="e.g. support" required>
                            </div>
                            <div class="form-group">
                                <label>Password</label>
                                <input type="password" id="acc-pass" placeholder="••••••••" required>
                            </div>
                            <div class="form-group">
                                <label>Quota (GB)</label>
                                <input type="number" id="acc-quota" value="10" min="1" required>
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary">Create Mailbox</button>
                    </form>
                </div>

                <div class="panel">
                    <div class="panel-header">
                        <h3>Mailbox Accounts & Storage Usage</h3>
                        <button class="btn btn-outline btn-sm" onclick="fetchAccounts()">Refresh</button>
                    </div>
                    <table>
                        <thead><tr><th>ID</th><th>Email Address</th><th>Disk Storage / Quota</th><th>Status</th><th>Actions</th></tr></thead>
                        <tbody id="table-accounts"><tr><td colspan="5">Loading accounts...</td></tr></tbody>
                    </table>
                </div>
            </div>

            <!-- TAB 5: ALIASES -->
            <div id="tab-aliases" class="tab-content">
                <div class="panel">
                    <div class="panel-header"><h3>Create Email Alias / Forwarder</h3></div>
                    <form onsubmit="addAlias(event)">
                        <div class="form-row">
                            <div class="form-group">
                                <label>Domain</label>
                                <select id="alias-domain" required></select>
                            </div>
                            <div class="form-group">
                                <label>Source Alias</label>
                                <input type="text" id="alias-src" placeholder="contact@example.com" required>
                            </div>
                            <div class="form-group">
                                <label>Destination Address (pisahkan koma jika > 1)</label>
                                <input type="text" id="alias-dst" placeholder="admin@example.com, john@example.com" required>
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary">Save Alias</button>
                    </form>
                </div>

                <div class="panel">
                    <div class="panel-header">
                        <h3>Active Aliases</h3>
                        <button class="btn btn-outline btn-sm" onclick="fetchAliases()">Refresh</button>
                    </div>
                    <table>
                        <thead><tr><th>ID</th><th>Source Alias</th><th>Destination Target</th><th>Status</th><th>Action</th></tr></thead>
                        <tbody id="table-aliases"><tr><td colspan="5">Loading aliases...</td></tr></tbody>
                    </table>
                </div>
            </div>

            <!-- TAB 6: DELIVERABILITY -->
            <div id="tab-deliverability" class="tab-content">
                <div class="panel">
                    <div class="panel-header"><h3>Live DNS & Deliverability Diagnostic Center</h3></div>
                    <p style="color: var(--text-muted); font-size: 13.5px; margin-bottom: 20px;">
                        Pilih domain untuk memeriksa apakah record <strong>MX, SPF, DKIM, dan DMARC</strong> sudah terpasang dan terbaca oleh DNS publik di seluruh dunia.
                    </p>
                    <div style="display: flex; gap: 14px; align-items: flex-end; margin-bottom: 24px;">
                        <div class="form-group" style="flex-grow: 1;">
                            <label>Pilih Domain untuk Dicek</label>
                            <select id="dns-check-domain"></select>
                        </div>
                        <button class="btn btn-primary" onclick="checkDNS()">Run Live DNS Verification</button>
                    </div>

                    <div id="dns-results" style="display: none;">
                        <table>
                            <thead><tr><th>Standard</th><th>Live Verification</th><th>Detected Record Value</th><th>Recommended Setup</th></tr></thead>
                            <tbody id="table-dns-results"></tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- TAB 7: QUEUE -->
            <div id="tab-queue" class="tab-content">
                <div class="panel">
                    <div class="panel-header">
                        <h3>Postfix Mail Queue Inspector</h3>
                        <div style="display: flex; gap: 10px;">
                            <button class="btn btn-outline btn-sm" onclick="flushQueue()">⚡ Flush Queue</button>
                            <button class="btn btn-danger btn-sm" onclick="deleteQueue('ALL')">🗑️ Purge All</button>
                        </div>
                    </div>
                    <table>
                        <thead><tr><th>Queue ID</th><th>Size</th><th>Date</th><th>Sender</th><th>Recipient</th><th>Error Reason</th><th>Action</th></tr></thead>
                        <tbody id="table-queue"><tr><td colspan="7">Loading queue...</td></tr></tbody>
                    </table>
                </div>
            </div>

            <!-- TAB 8: LOGS -->
            <div id="tab-logs" class="tab-content">
                <div class="panel">
                    <div class="panel-header">
                        <h3>Real-Time Postfix, Dovecot & Rspamd Logs</h3>
                        <button class="btn btn-outline btn-sm" onclick="fetchLogs()">🔄 Refresh Logs</button>
                    </div>
                    <div class="console-light" id="log-box">Fetching recent mail logs...</div>
                </div>
            </div>

            <!-- TAB 9: CONTENT & SPAM FILTER -->
            <div id="tab-filtering" class="tab-content">
                <div class="grid-kpi">
                    <div class="kpi-card">
                        <div class="kpi-header">
                            <span class="kpi-label">Spam Engine</span>
                            <div class="kpi-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
                        </div>
                        <div class="kpi-val" style="font-size: 22px;">Rspamd 3.8</div>
                        <div class="kpi-sub"><span class="tag-status tag-active"><span class="status-dot"></span> Active Milter (11332)</span></div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-header">
                            <span class="kpi-label">Mailbox Sieve Protocol</span>
                            <div class="kpi-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div>
                        </div>
                        <div class="kpi-val" style="font-size: 22px;">Port 4190</div>
                        <div class="kpi-sub"><span class="tag-status tag-active"><span class="status-dot"></span> ManageSieve Online</span></div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-header">
                            <span class="kpi-label">Dangerous File Blocker</span>
                            <div class="kpi-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg></div>
                        </div>
                        <div class="kpi-val" id="filter-kpi-ext" style="font-size: 22px;">11 Extensions</div>
                        <div class="kpi-sub">Blocked Scripts & Executables</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-header">
                            <span class="kpi-label">Filter Rules Engine</span>
                            <div class="kpi-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>
                        </div>
                        <div class="kpi-val" style="font-size: 22px;">Synchronized</div>
                        <div class="kpi-sub">Blacklist, Whitelist & Thresholds</div>
                    </div>
                </div>

                <!-- Panel 1: Attachment Security -->
                <div class="panel">
                    <div class="panel-header">
                        <div>
                            <h3>🛡️ Dangerous Attachment Policy (File Extension Blocker)</h3>
                            <p style="font-size: 12.5px; color: var(--text-muted); margin-top: 4px;">Email yang membawa lampiran dengan ekstensi di bawah ini akan otomatis DITOLAK (Reject) oleh Rspamd sebelum sampai ke mailbox.</p>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Ekstensi yang Diblokir (Pisahkan dengan koma atau spasi)</label>
                        <input type="text" id="filter-extensions" placeholder="exe, bat, cmd, scr, vbs, js, jar, ps1, hta, pif">
                    </div>
                </div>

                <!-- Panel 2: Sender Blacklist & Whitelist -->
                <div class="form-row" style="margin-bottom: 24px;">
                    <div class="panel" style="margin-bottom: 0;">
                        <div class="panel-header">
                            <div>
                                <h3 style="color: var(--danger);">⛔ Sender Blacklist (Auto-Reject)</h3>
                                <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Alamat email atau domain yang langsung diblokir (1 per baris, contoh: <code>@spam.com</code> atau <code>bot@evil.com</code>).</p>
                            </div>
                        </div>
                        <textarea id="filter-blacklist" rows="7" placeholder="@spamdomain.com&#10;spammer@domain.org" style="font-family: monospace;"></textarea>
                    </div>
                    <div class="panel" style="margin-bottom: 0;">
                        <div class="panel-header">
                            <div>
                                <h3 style="color: var(--success);">✅ Sender Whitelist (Bypass Filter)</h3>
                                <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Alamat email atau domain terpercaya yang di-bypass (1 per baris, contoh: <code>@partner.com</code>).</p>
                            </div>
                        </div>
                        <textarea id="filter-whitelist" rows="7" placeholder="@partner.com&#10;ceo@trusted-client.com" style="font-family: monospace;"></textarea>
                    </div>
                </div>

                <!-- Panel 3: Spam Thresholds & Subject Filter -->
                <div class="form-row" style="margin-bottom: 24px;">
                    <div class="panel" style="margin-bottom: 0;">
                        <div class="panel-header">
                            <h3>⚖️ Spam Sensitivity Thresholds (Rspamd)</h3>
                        </div>
                        <div class="form-group" style="margin-bottom: 12px;">
                            <label>Reject Score (Batas Skor Penolakan)</label>
                            <input type="number" step="0.5" id="filter-score-reject" value="15.0">
                            <small style="color: var(--text-muted); font-size: 11.5px;">Email dengan skor &ge; batas ini akan langsung ditolak Postfix (Default: 15.0)</small>
                        </div>
                        <div class="form-group" style="margin-bottom: 12px;">
                            <label>Add Header Score (Tandai X-Spam: Yes)</label>
                            <input type="number" step="0.5" id="filter-score-header" value="6.0">
                            <small style="color: var(--text-muted); font-size: 11.5px;">Email ditandai sebagai spam dan otomatis dipindah ke folder Junk (Default: 6.0)</small>
                        </div>
                        <div class="form-group">
                            <label>Greylist Score (Tunda Pengirim Baru)</label>
                            <input type="number" step="0.5" id="filter-score-greylist" value="4.0">
                            <small style="color: var(--text-muted); font-size: 11.5px;">Pengirim baru mencurigakan diminta coba kirim ulang setelah delay singkat (Default: 4.0)</small>
                        </div>
                    </div>

                    <div class="panel" style="margin-bottom: 0;">
                        <div class="panel-header">
                            <h3>🚫 Subject Keyword / Bad Words Filter</h3>
                        </div>
                        <div class="form-group">
                            <label>Kata Kunci / Regex Terlarang pada Judul Email (1 per baris)</label>
                            <textarea id="filter-subjects" rows="8" placeholder="/viagra/i&#10;/urgent wire transfer/i&#10;/claim inheritance/i" style="font-family: monospace;"></textarea>
                        </div>
                    </div>
                </div>

                <!-- Action Bar: Save Rules -->
                <div class="panel" style="background: linear-gradient(135deg, #eff6ff 0%, #f8fafc 100%); border: 1.5px solid #bfdbfe; display: flex; align-items: center; justify-content: space-between; padding: 22px 26px; margin-bottom: 24px; box-shadow: 0 4px 12px rgba(37,99,235,0.06);">
                    <div>
                        <h3 style="color: #1e40af; font-size: 16px; font-weight: 700; display: flex; align-items: center; gap: 8px;">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                            Terapkan Seluruh Konfigurasi Filter
                        </h3>
                        <p style="font-size: 13px; color: #475569; margin-top: 4px;">Perubahan pada ekstensi lampiran, blacklist, whitelist, threshold skor, dan kata kunci judul akan langsung disinkronkan ke Rspamd &amp; Postfix.</p>
                    </div>
                    <button class="btn btn-primary" onclick="saveFilterRules()" id="btn-save-filter-bottom" style="padding: 12px 24px; font-size: 14px; font-weight: 700; gap: 10px; box-shadow: 0 4px 14px rgba(37,99,235,0.35);">
                        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                        <span>Simpan Semua Aturan Filter</span>
                    </button>
                </div>

                <!-- Panel 4: Webmail Sieve User Rules -->
                <div class="panel">
                    <div class="panel-header">
                        <h3>📬 Individual User Filtering (Roundcube ManageSieve)</h3>
                    </div>
                    <p style="font-size: 13.5px; line-height: 1.6; color: var(--text-body);">
                        Pengguna email perorangan kini dapat membuat aturan filter inbox secara visual melalui <strong>EMXS Webmail (Roundcube)</strong> di:
                        <br>
                        <span style="display: inline-block; margin-top: 8px; padding: 6px 14px; background: var(--primary-light); color: var(--primary); border-radius: 8px; font-weight: 700;">
                            Settings ⚙️ &rarr; Filters (Penyaring)
                        </span>
                    </p>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-top: 14px;">
                        <div style="background: #f8fafc; border: 1px solid var(--border); border-radius: 9px; padding: 14px; font-size: 12.5px;">
                            <strong>📁 Auto-Folder Sorting</strong><br><span style="color: var(--text-muted);">Pindahkan email ke subfolder otomatis berdasarkan pengirim atau subjek.</span>
                        </div>
                        <div style="background: #f8fafc; border: 1px solid var(--border); border-radius: 9px; padding: 14px; font-size: 12.5px;">
                            <strong>🏖️ Vacation Responder</strong><br><span style="color: var(--text-muted);">Balas otomatis saat sedang cuti / out of office.</span>
                        </div>
                        <div style="background: #f8fafc; border: 1px solid var(--border); border-radius: 9px; padding: 14px; font-size: 12.5px;">
                            <strong>➡️ Auto-Forwarding</strong><br><span style="color: var(--text-muted);">Teruskan email penting ke alamat email lain secara real-time.</span>
                        </div>
                        <div style="background: #f8fafc; border: 1px solid var(--border); border-radius: 9px; padding: 14px; font-size: 12.5px;">
                            <strong>🗑️ Discard & Block</strong><br><span style="color: var(--text-muted);">Hapus pesan otomatis tanpa masuk ke inbox pengguna.</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TAB: EMAIL TRANSACTIONS & AUDIT LOG (MAX 30 DAYS) -->
            <div id="tab-transactions" class="tab-content">
                <!-- FILTER & SEARCH PANEL -->
                <div class="panel" style="margin-bottom: 24px;">
                    <div class="panel-header" style="margin-bottom: 16px;">
                        <div>
                            <h3>Pencarian &amp; Filter Audit Log Transaksi</h3>
                            <p style="font-size: 12.5px; color: var(--text-muted); margin-top: 2px;">Cari dan saring transaksi email inbound/outbound berdasarkan pengirim, penerima, subjek, status, dan rentang hari.</p>
                        </div>
                    </div>
                    <div class="form-row" style="margin-bottom: 0; align-items: flex-end;">
                        <div class="form-group" style="flex: 2; min-width: 200px;">
                            <label>Cari Pengirim / Penerima / Subjek</label>
                            <input type="text" id="tx-search" placeholder="Ketik kata kunci atau alamat email..." onkeydown="if(event.key==='Enter') fetchTransactions()">
                        </div>
                        <div class="form-group" style="flex: 1; min-width: 140px;">
                            <label>Status Transaksi</label>
                            <select id="tx-status" onchange="fetchTransactions()">
                                <option value="ALL">Semua Status</option>
                                <option value="DELIVERED">DELIVERED (Diterima)</option>
                                <option value="SENT">SENT (Terkirim)</option>
                                <option value="REJECTED">REJECTED (Ditolak)</option>
                                <option value="SPAM">SPAM (Ditandai Spam)</option>
                                <option value="GREYLISTED">GREYLISTED (Ditunda)</option>
                            </select>
                        </div>
                        <div class="form-group" style="flex: 1; min-width: 130px;">
                            <label>Arah (Direction)</label>
                            <select id="tx-direction" onchange="fetchTransactions()">
                                <option value="ALL">Semua Arah</option>
                                <option value="INBOUND">Masuk (Inbound)</option>
                                <option value="OUTBOUND">Keluar (Outbound)</option>
                            </select>
                        </div>
                        <div class="form-group" style="flex: 1; min-width: 140px;">
                            <label>Rentang Waktu</label>
                            <select id="tx-days" onchange="fetchTransactions()">
                                <option value="30" selected>30 Hari (Maksimal)</option>
                                <option value="14">14 Hari Terakhir</option>
                                <option value="7">7 Hari Terakhir</option>
                                <option value="1">24 Jam Terakhir</option>
                            </select>
                        </div>
                        <div style="display: flex; gap: 8px; flex: 0 0 auto;">
                            <button class="btn btn-primary" onclick="fetchTransactions()" style="height: 42px; padding: 0 18px;" title="Terapkan filter pencarian">
                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                                <span>Filter</span>
                            </button>
                            <button class="btn btn-outline" onclick="resetTxFilters()" style="height: 42px; padding: 0 16px;" title="Reset seluruh kolom filter">
                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
                                <span>Reset</span>
                            </button>
                        </div>
                    </div>
                </div>

                <!-- TRANSACTIONS TABLE PANEL -->
                <div class="panel">
                    <div class="panel-header">
                        <div>
                            <h3 id="tx-table-title">History Transaksi Email (30 Hari Terakhir)</h3>
                            <p style="font-size: 12.5px; color: var(--text-muted); margin-top: 2px;" id="tx-table-subtitle">Memuat data transaksi aktif...</p>
                        </div>
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span class="status-pill" id="tx-retention-pill">
                                <span class="status-dot"></span> Retensi Aktif: 30 Hari
                            </span>
                            <button class="btn btn-outline btn-sm" onclick="fetchTransactions()" style="padding: 6px 14px; gap: 6px;" title="Muat ulang data transaksi terbaru">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
                                <span>Segarkan Data</span>
                            </button>
                        </div>
                    </div>
                    <div style="overflow-x: auto;">
                        <table>
                            <thead>
                                <tr>
                                    <th>Waktu (WIB)</th>
                                    <th>Arah</th>
                                    <th>Pengirim (From)</th>
                                    <th>Penerima (To)</th>
                                    <th>Subjek</th>
                                    <th>Ukuran</th>
                                    <th>Skor Rspamd</th>
                                    <th>Status</th>
                                    <th style="text-align: center;">Aksi</th>
                                </tr>
                            </thead>
                            <tbody id="table-transactions">
                                <tr><td colspan="9" style="text-align: center; padding: 32px; color: var(--text-muted); font-size: 13.5px;"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2.5" class="spin" style="display:inline-block; vertical-align:middle; margin-right:10px;"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg><span>Memuat riwayat transaksi email...</span></td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- TAB 11: USER MANAGEMENT & 2FA -->
            <div id="tab-users" class="tab-content">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; flex-wrap:wrap; gap:12px;">
                    <div>
                        <h3 style="font-size:19px; font-weight:700; color:var(--text-title); margin:0 0 3px 0;">Dashboard User Management</h3>
                        <p style="font-size:13px; color:var(--text-muted); margin:0;">Kelola akun administrator dashboard dan konfigurasi Autentikasi Dua Langkah (OTP/2FA).</p>
                    </div>
                    <div style="display:flex; gap:10px;">
                        <button class="btn btn-outline btn-sm" onclick="fetchDashboardUsers()" style="padding:8px 14px; gap:6px;">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
                            <span>Segarkan</span>
                        </button>
                        <button class="btn btn-primary btn-sm" onclick="openAddUserModal()" style="padding:8px 16px; gap:6px;">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                            <span>Tambah Admin</span>
                        </button>
                    </div>
                </div>

                <div class="grid-kpi" style="margin-bottom:24px;">
                    <div class="kpi-card">
                        <div class="kpi-header"><span class="kpi-label">Total Akun Admin</span><div class="kpi-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div></div>
                        <div class="kpi-val" id="kpi-users-total">-</div>
                        <div class="kpi-sub">Administrator Terdaftar</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-header"><span class="kpi-label">Hak Superadmin</span><div class="kpi-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg></div></div>
                        <div class="kpi-val" id="kpi-users-super">-</div>
                        <div class="kpi-sub">Akses Penuh Sistem</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-header"><span class="kpi-label">2FA / OTP Status</span><div class="kpi-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div></div>
                        <div class="kpi-val" id="kpi-users-otp">-</div>
                        <div class="kpi-sub" style="color:var(--text-muted);">Default Nonaktif (Opsional)</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-header"><span class="kpi-label">Sesi Aktif</span><div class="kpi-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div></div>
                        <div class="kpi-val" id="kpi-users-sessions">-</div>
                        <div class="kpi-sub" style="color:var(--success);">Sesi Login Berjalan</div>
                    </div>
                </div>

                <div class="panel">
                    <div class="panel-header">
                        <div>
                            <h3>Daftar Administrator Dashboard</h3>
                            <p style="font-size:12.5px; color:var(--text-muted); margin-top:2px;">Akun yang memiliki hak akses untuk mengelola server EMXS.</p>
                        </div>
                    </div>
                    <div style="overflow-x: auto;">
                        <table>
                            <thead>
                                <tr>
                                    <th>Administrator</th>
                                    <th>Peran (Role)</th>
                                    <th>Status 2FA / OTP</th>
                                    <th>Terakhir Login</th>
                                    <th>Dibuat Pada</th>
                                    <th style="text-align:right;">Aksi</th>
                                </tr>
                            </thead>
                            <tbody id="table-users">
                                <tr><td colspan="6" style="text-align:center; padding:32px; color:var(--text-muted);"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2.2" class="spin" style="display:inline-block; vertical-align:middle; margin-right:8px;"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg><span>Memuat data pengguna...</span></td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- DNS Setup & DMARC/DKIM/SPF Guide Modal -->
    <div class="modal" id="modal-dkim">
        <div class="modal-card" style="max-width: 680px; max-height: 88vh; overflow-y: auto;">
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 14px;">
                <div style="width: 40px; height: 40px; border-radius: 10px; background: rgba(37,99,235,0.12); display: flex; align-items: center; justify-content: center; color: var(--primary);">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
                </div>
                <div>
                    <h3 style="margin: 0; color: var(--text-title); font-size: 18px; font-weight: 700;">Panduan DNS Record: DKIM, DMARC &amp; SPF</h3>
                    <p style="font-size: 12.5px; color: var(--text-muted); margin: 0;">Domain: <strong id="dns-modal-domain" style="color: var(--primary);">-</strong> &bull; Pasang record berikut di Cloudflare / DNS Provider Anda</p>
                </div>
            </div>

            <!-- PANEL 1: DKIM -->
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 14px 16px; margin-bottom: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div style="font-weight: 700; font-size: 13px; color: var(--text-title); display: flex; align-items: center; gap: 6px;">
                        <span>🔑 1. DKIM Record (Tanda Tangan Kriptografi)</span>
                    </div>
                    <span class="status-pill" style="background: #eff6ff; color: #1d4ed8; border-color: #bfdbfe; font-size: 11px;">Tipe: TXT</span>
                </div>
                <label style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase;">Host / Name</label>
                <div style="display: flex; justify-content: space-between; align-items: center; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 7px 10px; margin: 3px 0 8px 0; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--primary);">
                    <span id="dkim-host">appsmail._domainkey</span>
                    <button class="btn btn-outline btn-sm" onclick="copySnippetText('dkim-host', this)" style="padding: 3px 8px; font-size: 11px;">Salin</button>
                </div>
                <label style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase;">Value / Isi Record</label>
                <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px 10px; margin-top: 3px; font-family: 'JetBrains Mono', monospace; font-size: 11.5px; color: #334155; word-break: break-all; line-height: 1.4;">
                    <span id="dkim-val">-</span>
                    <button class="btn btn-outline btn-sm" onclick="copySnippetText('dkim-val', this)" style="padding: 3px 8px; font-size: 11px; flex-shrink: 0;">Salin</button>
                </div>
            </div>

            <!-- PANEL 2: DMARC GUIDE -->
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 14px 16px; margin-bottom: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div style="font-weight: 700; font-size: 13px; color: var(--text-title); display: flex; align-items: center; gap: 6px;">
                        <span>🛡️ 2. DMARC Record Guide (Proteksi Anti-Spoofing &amp; Kebijakan Email)</span>
                    </div>
                    <span class="status-pill" style="background: #fdf2f8; color: #be185d; border-color: #fbcfe8; font-size: 11px;">Tipe: TXT</span>
                </div>
                <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px; line-height: 1.4;">DMARC memberitahu server penerima (Gmail, Yahoo, Outlook) apa yang harus dilakukan jika ada email palsu yang gagal lolos validasi SPF/DKIM.</p>

                <label style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase;">Host / Name</label>
                <div style="display: flex; justify-content: space-between; align-items: center; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 7px 10px; margin: 3px 0 10px 0; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--primary);">
                    <span>_dmarc</span>
                    <button class="btn btn-outline btn-sm" onclick="copyRawText('_dmarc', this)" style="padding: 3px 8px; font-size: 11px;">Salin Host</button>
                </div>

                <div style="margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 3px;">
                        <span style="font-size: 11.5px; font-weight: 700; color: #1e40af;">Opsi A: Kebijakan Karantina (Disarankan — Masuk Spam jika Palsu)</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px; background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 7px 10px; font-family: 'JetBrains Mono', monospace; font-size: 11.5px; color: #1e40af;">
                        <span id="dmarc-val-quarantine">v=DMARC1; p=quarantine; sp=quarantine; aspf=r;</span>
                        <button class="btn btn-primary btn-sm" onclick="copySnippetText('dmarc-val-quarantine', this)" style="padding: 3px 8px; font-size: 11px; flex-shrink: 0;">Salin</button>
                    </div>
                </div>

                <div style="margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 3px;">
                        <span style="font-size: 11.5px; font-weight: 700; color: #991b1b;">Opsi B: Kebijakan Reject (Proteksi Penuh — Tolak Langsung)</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px; background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 7px 10px; font-family: 'JetBrains Mono', monospace; font-size: 11.5px; color: #991b1b;">
                        <span id="dmarc-val-reject">v=DMARC1; p=reject; sp=reject; aspf=s;</span>
                        <button class="btn btn-outline btn-sm" onclick="copySnippetText('dmarc-val-reject', this)" style="padding: 3px 8px; font-size: 11px; flex-shrink: 0;">Salin</button>
                    </div>
                </div>

                <div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 3px;">
                        <span style="font-size: 11.5px; font-weight: 600; color: #475569;">Opsi C: Kebijakan Monitoring Saja (p=none)</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 7px 10px; font-family: 'JetBrains Mono', monospace; font-size: 11.5px; color: #475569;">
                        <span id="dmarc-val-none">v=DMARC1; p=none; sp=none;</span>
                        <button class="btn btn-outline btn-sm" onclick="copySnippetText('dmarc-val-none', this)" style="padding: 3px 8px; font-size: 11px; flex-shrink: 0;">Salin</button>
                    </div>
                </div>
            </div>

            <!-- PANEL 3: SPF & MX -->
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 18px;">
                <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 12px 14px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-weight: 700; font-size: 12.5px; color: var(--text-title);">📨 3. SPF Record</span>
                        <span class="status-pill" style="font-size: 10px; padding: 2px 6px;">TXT (@)</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; gap: 6px; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 6px 8px; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--primary);">
                        <span id="spf-val">v=spf1 +mx +ip4:103.147.157.37 ~all</span>
                        <button class="btn btn-outline btn-sm" onclick="copySnippetText('spf-val', this)" style="padding: 2px 6px; font-size: 10px; flex-shrink: 0;">Salin</button>
                    </div>
                    <div style="font-size: 10.5px; color: #64748b; margin-top: 5px; line-height: 1.3;">Tips: Sisipkan <code>+ip4:IP_LAIN</code> sebelum <code>~all</code> jika punya IP pengirim tambahan</div>
                </div>

                <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 12px 14px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-weight: 700; font-size: 12.5px; color: var(--text-title);">📮 4. MX Record</span>
                        <span class="status-pill" style="font-size: 10px; padding: 2px 6px;">MX (Pri: 10)</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; gap: 6px; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 6px 8px; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--primary);">
                        <span id="mx-val">mail.elsw-studio.my.id</span>
                        <button class="btn btn-outline btn-sm" onclick="copySnippetText('mx-val', this)" style="padding: 2px 6px; font-size: 10px; flex-shrink: 0;">Salin</button>
                    </div>
                    <div style="font-size: 10.5px; color: #64748b; margin-top: 5px; line-height: 1.3;">Host: <code>@</code> | Target mail server utama penerimaan email</div>
                </div>
            </div>

            <div style="display: flex; justify-content: flex-end;">
                <button class="btn btn-primary" style="padding: 9px 24px;" onclick="closeModal()">
                    <span>Selesai / Tutup Panduan</span>
                </button>
            </div>
        </div>
    </div>

    <!-- Password Modal -->
    <div class="modal" id="modal-pass">
        <div class="modal-card">
            <h3 style="margin-bottom: 10px; color: var(--text-title); font-size: 18px;">Reset Password Mailbox</h3>
            <div class="form-group" style="margin-bottom: 16px;">
                <label id="pass-modal-email">New Password</label>
                <input type="password" id="pass-new" placeholder="Enter new strong password" required>
            </div>
            <div style="display: flex; gap: 10px;">
                <button class="btn btn-primary" style="flex-grow: 1;" onclick="submitPasswordChange()">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    <span>Simpan Password</span>
                </button>
                <button class="btn btn-outline" onclick="closePassModal()">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
                    <span>Batal</span>
                </button>
            </div>
        </div>
    </div>

    <!-- Email Reader Modal -->
    <div class="modal" id="modal-read-email">
        <div class="modal-card" style="max-width: 780px; padding: 28px;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 16px; border-bottom: 1px solid var(--border-light); padding-bottom: 16px;">
                <div>
                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                        <span class="status-pill" style="background: #eff6ff; color: #2563eb; border-color: #bfdbfe; font-size: 11px;">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
                            Surat Masuk (Maildir)
                        </span>
                        <span style="font-size: 12px; color: var(--text-muted);" id="read-date">-</span>
                    </div>
                    <h2 id="read-subject" style="font-size: 19px; font-weight: 700; color: var(--text-title); line-height: 1.3;">-</h2>
                </div>
                <button class="btn btn-outline btn-sm" onclick="closeReadModal()" style="border-radius: 8px; padding: 6px 10px;" title="Tutup">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
                </button>
            </div>
            
            <div style="display: flex; align-items: center; justify-content: space-between; background: #f8fafc; border: 1px solid var(--border-light); border-radius: 10px; padding: 12px 16px; margin-bottom: 16px;">
                <div style="display: flex; align-items: center; gap: 12px;">
                    <div style="width: 38px; height: 38px; border-radius: 50%; background: linear-gradient(135deg, #2563eb, #4f46e5); color: #fff; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 15px;" id="read-avatar">@</div>
                    <div>
                        <div style="font-size: 13.5px; font-weight: 700; color: var(--text-title);" id="read-from">-</div>
                        <div style="font-size: 12px; color: var(--text-muted);">Kepada: <span id="read-to" style="color: #334155; font-weight: 600;">-</span></div>
                    </div>
                </div>
            </div>

            <div id="read-body" style="background: #ffffff; border: 1px solid var(--border); border-radius: 12px; padding: 22px; font-size: 14px; line-height: 1.7; min-height: 180px; max-height: 420px; overflow-y: auto; white-space: pre-wrap; word-break: break-word; color: #1e293b; font-family: 'Plus Jakarta Sans', sans-serif;"></div>

            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 20px; gap: 12px;">
                <div style="display: flex; gap: 10px;">
                    <button class="btn btn-primary" onclick="replyCurrentEmail()">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/></svg>
                        <span>Balas Email</span>
                    </button>
                    <a href="/webmail/" target="_blank" class="btn btn-outline" style="text-decoration: none;">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
                        <span>Buka di Webmail ↗</span>
                    </a>
                </div>
                <button class="btn btn-outline" onclick="closeReadModal()">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
                    <span>Tutup</span>
                </button>
            </div>
        </div>
    </div>

    <!-- Transaction Detail Modal -->
    <div class="modal" id="modal-tx-detail">
        <div class="modal-card" style="max-width: 680px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border);">
                <div>
                    <h3 style="color: var(--text-title); font-size: 17px; font-weight: 700; display: flex; align-items: center; gap: 8px;">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2.2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                        <span>Audit Log Transaksi Email</span>
                    </h3>
                    <p style="font-size: 12px; color: var(--text-muted); margin-top: 2px;" id="modal-tx-id">ID Transaksi: -</p>
                </div>
                <button class="btn btn-outline btn-sm" onclick="closeTxDetailModal()" style="padding: 6px 10px;">✕</button>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 16px;">
                <div style="background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid var(--border-light);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Waktu Transaksi</div>
                    <div style="font-size: 13.5px; font-weight: 600; color: var(--text-title); margin-top: 4px;" id="modal-tx-time">-</div>
                </div>
                <div style="background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid var(--border-light);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Status &amp; Arah</div>
                    <div style="margin-top: 4px; display: flex; gap: 6px; align-items: center;" id="modal-tx-status-wrap">-</div>
                </div>
            </div>

            <div style="display: flex; flex-direction: column; gap: 10px; margin-bottom: 16px;">
                <div style="background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid var(--border-light);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Pengirim (From)</div>
                    <div style="font-size: 13px; font-weight: 600; color: #1e3a8a; margin-top: 3px; word-break: break-all;" id="modal-tx-sender">-</div>
                </div>
                <div style="background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid var(--border-light);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Penerima (To)</div>
                    <div style="font-size: 13px; font-weight: 600; color: #047857; margin-top: 3px; word-break: break-all;" id="modal-tx-rcpt">-</div>
                </div>
                <div style="background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid var(--border-light);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Subjek</div>
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-title); margin-top: 3px;" id="modal-tx-subject">-</div>
                </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin-bottom: 16px;">
                <div style="background: #f8fafc; padding: 10px; border-radius: 8px; border: 1px solid var(--border-light);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--text-muted);">IP Klien / Relay</div>
                    <div style="font-size: 12.5px; font-family: monospace; font-weight: 600; margin-top: 3px;" id="modal-tx-ip">-</div>
                </div>
                <div style="background: #f8fafc; padding: 10px; border-radius: 8px; border: 1px solid var(--border-light);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--text-muted);">Ukuran Pesan</div>
                    <div style="font-size: 12.5px; font-weight: 600; margin-top: 3px;" id="modal-tx-size">-</div>
                </div>
                <div style="background: #f8fafc; padding: 10px; border-radius: 8px; border: 1px solid var(--border-light);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--text-muted);">Rspamd Spam Score</div>
                    <div style="font-size: 12.5px; font-weight: 700; margin-top: 3px;" id="modal-tx-score">-</div>
                </div>
            </div>

            <div style="margin-bottom: 16px;">
                <label style="font-size: 12px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Message-ID</label>
                <div class="code-snippet" id="modal-tx-msgid" style="margin-top: 4px; margin-bottom: 12px; font-size: 11.5px;">-</div>
            </div>

            <div style="margin-bottom: 18px;">
                <label style="font-size: 12px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Detail Filter &amp; Eksekusi</label>
                <div style="background: #0f172a; color: #38bdf8; border-radius: 8px; padding: 12px; font-family: 'JetBrains Mono', monospace; font-size: 11.5px; line-height: 1.5; max-height: 140px; overflow-y: auto; word-break: break-all;" id="modal-tx-details">-</div>
            </div>

            <div style="display: flex; justify-content: flex-end;">
                <button class="btn btn-outline" onclick="closeTxDetailModal()">Tutup Detail</button>
            </div>
        </div>
    </div>

    <!-- Modal Tambah Admin -->
    <div class="modal" id="modal-add-user">
        <div class="modal-card">
            <h3 style="margin-bottom: 8px; color: var(--text-title); font-size: 18px;">Tambah Administrator Baru</h3>
            <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">Buat akun admin baru untuk mengakses dashboard EMXS.</p>
            <div class="form-group" style="margin-bottom: 14px;">
                <label>Username</label>
                <input type="text" id="add-user-username" placeholder="noc_admin" autocomplete="off">
            </div>
            <div class="form-group" style="margin-bottom: 14px;">
                <label>Alamat Email</label>
                <input type="email" id="add-user-email" placeholder="admin@elsw-studio.my.id">
            </div>
            <div class="form-group" style="margin-bottom: 14px;">
                <label>Kata Sandi (Password)</label>
                <input type="password" id="add-user-password" placeholder="Minimal 6 karakter">
            </div>
            <div class="form-group" style="margin-bottom: 16px;">
                <label>Peran (Role)</label>
                <select id="add-user-role" style="width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; font-size: 14px; background: #fff;">
                    <option value="admin">Administrator (Standar)</option>
                    <option value="superadmin">Superadmin (Akses Penuh)</option>
                </select>
            </div>
            <div style="background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 10px 12px; font-size: 12px; color: #1e40af; margin-bottom: 18px; line-height: 1.4;">
                <strong>Catatan OTP:</strong> Akun baru dibuat dengan status OTP Nonaktif secara default. Admin dapat mengaktifkan 2FA kapan saja melalui tombol Kelola OTP.
            </div>
            <div style="display: flex; justify-content: flex-end; gap: 10px;">
                <button class="btn btn-outline" onclick="closeAddUserModal()">Batal</button>
                <button class="btn btn-primary" onclick="submitAddUser()">Simpan Administrator</button>
            </div>
        </div>
    </div>

    <!-- Modal Reset Password Admin -->
    <div class="modal" id="modal-user-pass">
        <div class="modal-card">
            <h3 style="margin-bottom: 8px; color: var(--text-title); font-size: 18px;">Reset Password Administrator</h3>
            <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">Perbarui kata sandi untuk akun <strong id="reset-user-target" style="color: var(--primary);">-</strong></p>
            <input type="hidden" id="reset-user-id" value="0">
            <div class="form-group" style="margin-bottom: 14px;">
                <label>Kata Sandi Baru</label>
                <input type="password" id="reset-user-newpass" placeholder="Minimal 6 karakter">
            </div>
            <div class="form-group" style="margin-bottom: 18px;">
                <label>Konfirmasi Sandi Baru</label>
                <input type="password" id="reset-user-confirmpass" placeholder="Ketik ulang kata sandi">
            </div>
            <div style="display: flex; justify-content: flex-end; gap: 10px;">
                <button class="btn btn-outline" onclick="closeUserPassModal()">Batal</button>
                <button class="btn btn-primary" onclick="submitUserPass()">Perbarui Kata Sandi</button>
            </div>
        </div>
    </div>

    <!-- Modal Setup & Toggle OTP / 2FA -->
    <div class="modal" id="modal-user-otp">
        <div class="modal-card" style="max-width: 580px;">
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 14px;">
                <div style="width: 38px; height: 38px; border-radius: 10px; background: rgba(37,99,235,0.12); display: flex; align-items: center; justify-content: center; color: var(--primary);">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                <div>
                    <h3 style="margin: 0; color: var(--text-title); font-size: 18px;">Pengaturan 2FA / OTP</h3>
                    <p style="font-size: 12.5px; color: var(--text-muted); margin: 0;">Akun: <strong id="otp-modal-target" style="color: var(--primary);">-</strong></p>
                </div>
            </div>
            <input type="hidden" id="otp-modal-user-id" value="0">

            <!-- State A: Saat ini Aktif -->
            <div id="otp-state-active" style="display: none;">
                <div style="background: #ecfdf5; border: 1px solid #a7f3d0; border-radius: 12px; padding: 16px; margin-bottom: 20px; text-align: center;">
                    <div style="display: inline-flex; align-items: center; gap: 8px; color: #065f46; font-weight: 700; font-size: 15px; margin-bottom: 4px;">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                        <span>OTP / 2FA Sedang Aktif</span>
                    </div>
                    <p style="font-size: 12.5px; color: #047857; margin: 0; line-height: 1.5;">Akun ini diamankan dengan Autentikasi Dua Langkah. Kode 6 digit dari aplikasi Authenticator wajib dimasukkan setiap kali login.</p>
                </div>
                <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 20px;">Jika Anda ingin menonaktifkan verifikasi dua langkah untuk akun ini, klik tombol di bawah:</p>
                <div style="display: flex; justify-content: flex-end; gap: 10px;">
                    <button class="btn btn-outline" onclick="closeOTPModal()">Tutup</button>
                    <button class="btn btn-danger" onclick="disableOTP()">Nonaktifkan 2FA</button>
                </div>
            </div>

            <!-- State B: Saat ini Nonaktif (Default) -->
            <div id="otp-state-inactive" style="display: none;">
                <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 16px; margin-bottom: 20px;">
                    <span style="display: inline-block; font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase; margin-bottom: 6px; letter-spacing: 0.5px;">Langkah 1: Masukkan Secret Key ke Authenticator</span>
                    <p style="font-size: 12.5px; color: #64748b; margin-bottom: 10px; line-height: 1.4;">Buka Google Authenticator, Microsoft Authenticator, atau Authy, lalu masukkan Secret Key berikut:</p>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <div id="otp-secret-display" style="flex: 1; background: #0f172a; color: #38bdf8; font-family: 'JetBrains Mono', monospace; font-size: 13px; font-weight: 600; padding: 11px 14px; border-radius: 8px; letter-spacing: 1.2px; text-align: center; white-space: nowrap; overflow-x: auto;">-</div>
                        <button class="btn btn-outline btn-sm" onclick="copyOTPSecret()" id="btn-copy-secret" style="padding: 10px 14px; flex-shrink: 0; font-weight: 600;">Salin Key</button>
                    </div>
                </div>

                <div class="form-group" style="margin-bottom: 20px;">
                    <label style="font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase; letter-spacing: 0.5px;">Langkah 2: Masukkan 6 Digit Kode Konfirmasi</label>
                    <p style="font-size: 12.5px; color: #64748b; margin-bottom: 10px;">Ketikkan 6 digit angka yang muncul di aplikasi Authenticator untuk menguji & mengaktifkan:</p>
                    <input type="text" id="otp-confirm-code" placeholder="Contoh: 123456" maxlength="6" inputmode="numeric" style="font-family: 'JetBrains Mono', monospace; font-size: 22px; letter-spacing: 8px; text-align: center; padding: 12px; font-weight: 700; border-radius: 8px;">
                </div>

                <div style="display: flex; justify-content: flex-end; gap: 10px;">
                    <button class="btn btn-outline" onclick="closeOTPModal()">Batal</button>
                    <button class="btn btn-primary" onclick="submitEnableOTP()">Aktifkan 2FA Sekarang</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        function escapeHtml(str) {
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        let currentPassAccId = 0;
        let accountsCache = [];

        function nav(tabId) {
            document.querySelectorAll('.tab-content').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.nav-link').forEach(i => i.classList.remove('active'));
            const activeTab = document.getElementById('tab-' + tabId);
            if (activeTab) activeTab.classList.add('active');

            document.querySelectorAll('.nav-link').forEach(link => {
                if (link.getAttribute('onclick') === "nav('" + tabId + "')") {
                    link.classList.add('active');
                }
            });

            const titles = {
                'dashboard': 'System Overview & Metrics',
                'transactions': 'Email Transaction History & Audit Log (Maksimal 30 Hari)',
                'webmail': 'Webmail Client & Deliverability Tester',
                'domains': 'Virtual Domains Management',
                'mailboxes': 'Mailbox Accounts & Storage',
                'aliases': 'Aliases & Forwarding Rules',
                'deliverability': 'DNS Deliverability Wizard (SPF / DKIM / DMARC)',
                'filtering': 'Content & Spam Filter Engine (Rspamd + Sieve)',
                'queue': 'Postfix Mail Queue Inspector',
                'logs': 'Real-Time Server Logs',
                'users': 'User Management & Keamanan OTP/2FA'
            };
            document.getElementById('header-text').innerText = titles[tabId] || 'EMXS Studio';

            if (tabId === 'logs') fetchLogs();
            if (tabId === 'queue') fetchQueue();
            if (tabId === 'webmail') fetchInbox();
            if (tabId === 'filtering') fetchFilterRules();
            if (tabId === 'transactions') fetchTransactions();
            if (tabId === 'users') fetchDashboardUsers();
        }

        async function fetchFilterRules() {
            try {
                const res = await fetch('/api/filter/rules');
                const data = await res.json();
                document.getElementById('filter-extensions').value = (data.bad_extensions || []).join(', ');
                document.getElementById('filter-blacklist').value = (data.blacklist_senders || []).join('\n');
                document.getElementById('filter-whitelist').value = (data.whitelist_senders || []).join('\n');
                document.getElementById('filter-subjects').value = (data.bad_subjects || []).join('\n');
                document.getElementById('filter-score-reject').value = data.score_reject || 15.0;
                document.getElementById('filter-score-header').value = data.score_add_header || 6.0;
                document.getElementById('filter-score-greylist').value = data.score_greylist || 4.0;
                if (data.bad_extensions) {
                    document.getElementById('filter-kpi-ext').innerText = data.bad_extensions.length + ' Extensions';
                }
            } catch(e) { console.error('Error fetching filter rules:', e); }
        }

        async function saveFilterRules() {
            const btns = [document.getElementById('btn-save-filter-top'), document.getElementById('btn-save-filter-bottom')].filter(Boolean);
            btns.forEach(b => {
                b.disabled = true;
                b.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg><span>Menyimpan ke Rspamd...</span>';
            });

            const extStr = document.getElementById('filter-extensions').value;
            const exts = extStr.split(/[\s,]+/).map(s => s.trim().replace(/^\./, '')).filter(Boolean);
            const blacklist = document.getElementById('filter-blacklist').value.split('\n').map(s => s.trim()).filter(Boolean);
            const whitelist = document.getElementById('filter-whitelist').value.split('\n').map(s => s.trim()).filter(Boolean);
            const subjects = document.getElementById('filter-subjects').value.split('\n').map(s => s.trim()).filter(Boolean);
            const reject = parseFloat(document.getElementById('filter-score-reject').value) || 15.0;
            const header = parseFloat(document.getElementById('filter-score-header').value) || 6.0;
            const greylist = parseFloat(document.getElementById('filter-score-greylist').value) || 4.0;

            const payload = {
                bad_extensions: exts,
                blacklist_senders: blacklist,
                whitelist_senders: whitelist,
                bad_subjects: subjects,
                score_reject: reject,
                score_add_header: header,
                score_greylist: greylist
            };

            try {
                const res = await fetch('/api/filter/rules', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(payload)
                });
                const resData = await res.json();
                alert(resData.message || 'Aturan filter berhasil disimpan dan disinkronkan ke Rspamd!');
                fetchFilterRules();
            } catch(e) {
                alert('Gagal menyimpan aturan filter: ' + e);
            } finally {
                btns.forEach(b => {
                    b.disabled = false;
                    b.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg><span>Simpan Semua Aturan Filter</span>';
                });
            }
        }

        async function fetchWithTimeout(url, opts = {}) {
            const timeout = opts.timeout || 4000;
            const controller = new AbortController();
            const id = setTimeout(() => controller.abort(), timeout);
            try {
                const res = await fetch(url, Object.assign({}, opts, { signal: controller.signal }));
                clearTimeout(id);
                return res;
            } catch (err) {
                clearTimeout(id);
                throw err;
            }
        }

        async function fetchStats() {
            try {
                const res = await fetchWithTimeout('/api/stats', { timeout: 3500 });
                if (!res.ok) return;
                const data = await res.json();
                document.getElementById('kpi-domains').innerText = data.total_domains;
                document.getElementById('kpi-accounts').innerText = data.total_accounts;
                document.getElementById('kpi-aliases').innerText = data.total_aliases;
                document.getElementById('kpi-queue').innerText = data.queue_count;
                document.getElementById('val-disk').innerText = data.disk_used + ' (' + data.disk_percent + ')';
                document.getElementById('val-uptime').innerText = data.uptime;

                const tbody = document.getElementById('table-services');
                tbody.innerHTML = '';
                (data.services || []).forEach(s => {
                    const statusBadge = s.running ? '<span class="tag-status tag-active">● Running</span>' : '<span class="tag-status tag-inactive">● Stopped</span>';
                    tbody.innerHTML += '<tr><td><strong>' + s.name + '</strong></td><td><code>' + s.port + '</code></td><td>' + statusBadge + '</td></tr>';
                });
            } catch (e) {
                console.warn('fetchStats error:', e);
            }

            try {
                const txRes = await fetchWithTimeout('/api/transactions/stats', { timeout: 3500 });
                if (txRes.ok) {
                    const tStats = await txRes.json();
                    if (document.getElementById('kpi-tx-total')) document.getElementById('kpi-tx-total').innerText = tStats.total_month || 0;
                    if (document.getElementById('kpi-tx-delivered')) document.getElementById('kpi-tx-delivered').innerText = (tStats.total_delivered || 0) + (tStats.total_sent || 0);
                    if (document.getElementById('kpi-tx-delivered-sub')) document.getElementById('kpi-tx-delivered-sub').innerText = (tStats.total_sent || 0) + ' Terkirim | ' + (tStats.total_delivered || 0) + ' Diterima';
                    if (document.getElementById('kpi-tx-rejected')) document.getElementById('kpi-tx-rejected').innerText = (tStats.total_rejected || 0) + (tStats.total_spam || 0);
                    if (document.getElementById('kpi-tx-rejected-sub')) document.getElementById('kpi-tx-rejected-sub').innerText = (tStats.total_spam || 0) + ' Spam | ' + (tStats.total_rejected || 0) + ' Rejected';
                    
                    const archFiles = tStats.archived_files || 0;
                    if (document.getElementById('kpi-tx-archives')) document.getElementById('kpi-tx-archives').innerText = archFiles + ' File';
                    let sizeStr = '0 KB';
                    if (tStats.archived_bytes > 1024*1024) {
                        sizeStr = (tStats.archived_bytes / (1024*1024)).toFixed(2) + ' MB';
                    } else if (tStats.archived_bytes > 0) {
                        sizeStr = (tStats.archived_bytes / 1024).toFixed(1) + ' KB';
                    }
                    if (document.getElementById('kpi-tx-archives-size')) document.getElementById('kpi-tx-archives-size').innerText = sizeStr + ' dikompresi (.json.gz)';
                }
            } catch(e) {
                console.warn('fetchTxStats in dashboard error:', e);
            }
        }

        async function fetchDomains() {
            try {
                const res = await fetchWithTimeout('/api/domains', { timeout: 3500 });
                if (!res.ok) return;
                const data = await res.json() || [];
                const tbody = document.getElementById('table-domains');
                const accSelect = document.getElementById('acc-domain');
                const aliasSelect = document.getElementById('alias-domain');
                const dnsSelect = document.getElementById('dns-check-domain');

                accSelect.innerHTML = '<option value="">Pilih Domain</option>';
                aliasSelect.innerHTML = '<option value="">Pilih Domain</option>';
                dnsSelect.innerHTML = '<option value="">Pilih Domain</option>';
                tbody.innerHTML = '';

                data.forEach(d => {
                    accSelect.innerHTML += '<option value="' + d.id + '">' + d.name + '</option>';
                    aliasSelect.innerHTML += '<option value="' + d.id + '">' + d.name + '</option>';
                    dnsSelect.innerHTML += '<option value="' + d.name + '">' + d.name + '</option>';
                    tbody.innerHTML += '<tr><td>' + d.id + '</td><td><strong>' + d.name + '</strong></td><td>' + d.user_count + ' Akun</td><td><span class="tag-status tag-active">● Aktif</span></td><td><button class="btn btn-outline btn-sm" onclick="showDKIM(\'' + d.name + '\')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><path d="m10 15 5-3-5-3v6Z"/></svg><span>DKIM &amp; DMARC DNS</span></button> <button class="btn btn-danger btn-sm" onclick="deleteDomain(' + d.id + ')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg><span>Hapus</span></button></td></tr>';
                });
            } catch (e) {
                console.warn('fetchDomains error:', e);
            }
        }

        async function fetchAccounts() {
            try {
                const res = await fetchWithTimeout('/api/accounts', { timeout: 3500 });
                if (!res.ok) return;
                const data = await res.json() || [];
                accountsCache = data;
                const tbody = document.getElementById('table-accounts');
                const wmSelect = document.getElementById('wm-inbox-email');
                const wmFromInput = document.getElementById('wm-from');

                tbody.innerHTML = '';
                wmSelect.innerHTML = '';

                data.forEach(a => {
                    wmSelect.innerHTML += '<option value="' + a.email + '">' + a.email + '</option>';
                    const quotaGB = Math.round(a.quota_bytes / (1024*1024*1024));
                    const usedMB = (a.used_bytes / (1024*1024)).toFixed(1);
                    tbody.innerHTML += '<tr><td>' + a.id + '</td><td><strong>' + a.email + '</strong></td><td>' + usedMB + ' MB / ' + quotaGB + ' GB</td><td><span class="tag-status tag-active">● Enabled</span></td><td><button class="btn btn-outline btn-sm" onclick="openPassModal(' + a.id + ', \'' + a.email + '\')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span>Ganti Pass</span></button> <button class="btn btn-danger btn-sm" onclick="deleteAccount(' + a.id + ')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg><span>Hapus</span></button></td></tr>';
                });

                if (data.length > 0 && !wmFromInput.value) {
                    wmFromInput.value = data[0].email;
                }
            } catch (e) {
                console.warn('fetchAccounts error:', e);
            }
        }

        async function fetchAliases() {
            try {
                const res = await fetchWithTimeout('/api/aliases', { timeout: 3500 });
                if (!res.ok) return;
                const data = await res.json() || [];
                const tbody = document.getElementById('table-aliases');
                tbody.innerHTML = '';
                data.forEach(a => {
                    tbody.innerHTML += '<tr><td>' + a.id + '</td><td><strong>' + a.source + '</strong></td><td>' + a.destination + '</td><td><span class="tag-status tag-active">● Aktif</span></td><td><button class="btn btn-danger btn-sm" onclick="deleteAlias(' + a.id + ')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg><span>Hapus</span></button></td></tr>';
                });
            } catch (e) {
                console.warn('fetchAliases error:', e);
            }
        }

        async function addDomain(e) {
            e.preventDefault();
            const name = document.getElementById('dom-name').value;
            const res = await fetch('/api/domains', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name})
            });
            if (res.ok) {
                document.getElementById('dom-name').value = '';
                refreshAll();
                alert('Domain berhasil ditambahkan! Record DKIM otomatis dibuat.');
            } else {
                const err = await res.json();
                alert('Error: ' + err.error);
            }
        }

        async function addAccount(e) {
            e.preventDefault();
            const domain_id = parseInt(document.getElementById('acc-domain').value);
            const username = document.getElementById('acc-user').value;
            const password = document.getElementById('acc-pass').value;
            const quota_gb = parseInt(document.getElementById('acc-quota').value);
            const res = await fetch('/api/accounts', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({domain_id, username, password, quota_gb})
            });
            if (res.ok) {
                document.getElementById('acc-user').value = '';
                document.getElementById('acc-pass').value = '';
                refreshAll();
                alert('Akun email berhasil dibuat!');
            } else {
                const err = await res.json();
                alert('Error: ' + err.error);
            }
        }

        async function addAlias(e) {
            e.preventDefault();
            const domain_id = parseInt(document.getElementById('alias-domain').value);
            const source = document.getElementById('alias-src').value;
            const destination = document.getElementById('alias-dst').value;
            const res = await fetch('/api/aliases', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({domain_id, source, destination})
            });
            if (res.ok) {
                document.getElementById('alias-src').value = '';
                document.getElementById('alias-dst').value = '';
                refreshAll();
                alert('Alias berhasil dibuat!');
            } else {
                const err = await res.json();
                alert('Error: ' + err.error);
            }
        }

        async function deleteDomain(id) {
            if (!confirm('Hapus domain dan seluruh mailbox di dalamnya?')) return;
            await fetch('/api/domains?id=' + id, {method: 'DELETE'});
            refreshAll();
        }

        async function deleteAccount(id) {
            if (!confirm('Hapus akun email ini?')) return;
            await fetch('/api/accounts?id=' + id, {method: 'DELETE'});
            refreshAll();
        }

        async function deleteAlias(id) {
            if (!confirm('Hapus alias ini?')) return;
            await fetch('/api/aliases?id=' + id, {method: 'DELETE'});
            refreshAll();
        }

        function copySnippetText(id, btn) {
            const el = document.getElementById(id);
            if (!el) return;
            copyRawText(el.innerText, btn);
        }

        function copyRawText(val, btn) {
            navigator.clipboard.writeText(val).then(function() {
                if (btn) {
                    const orig = btn.innerText;
                    btn.innerText = 'Tersalin!';
                    btn.style.color = '#10b981';
                    setTimeout(function() {
                        btn.innerText = orig;
                        btn.style.color = '';
                    }, 1500);
                }
            });
        }

        async function showDKIM(domain) {
            const modalDomain = document.getElementById('dns-modal-domain');
            if (modalDomain) modalDomain.innerText = domain;

            // Populate DMARC options dynamically with domain
            const dmarcQuar = document.getElementById('dmarc-val-quarantine');
            if (dmarcQuar) dmarcQuar.innerText = 'v=DMARC1; p=quarantine; rua=mailto:admin@' + domain + '; sp=quarantine; aspf=r;';
            const dmarcRej = document.getElementById('dmarc-val-reject');
            if (dmarcRej) dmarcRej.innerText = 'v=DMARC1; p=reject; rua=mailto:admin@' + domain + '; sp=reject; aspf=s;';
            const dmarcNone = document.getElementById('dmarc-val-none');
            if (dmarcNone) dmarcNone.innerText = 'v=DMARC1; p=none; rua=mailto:admin@' + domain + '; sp=none;';

            // Populate SPF and MX
            const spfEl = document.getElementById('spf-val');
            if (spfEl) spfEl.innerText = 'v=spf1 +mx +ip4:103.147.157.37 ~all';
            const mxEl = document.getElementById('mx-val');
            if (mxEl) mxEl.innerText = 'mail.elsw-studio.my.id';

            const hostEl = document.getElementById('dkim-host');
            const valEl = document.getElementById('dkim-val');
            if (hostEl) hostEl.innerText = 'appsmail._domainkey.' + domain;
            if (valEl) valEl.innerText = 'Memuat kunci DKIM dari server...';

            const m = document.getElementById('modal-dkim');
            if (m) {
                m.style.display = 'flex';
                m.classList.add('active');
            }

            try {
                const res = await fetch('/api/dkim/generate?domain=' + domain);
                const data = await res.json();
                if (hostEl) hostEl.innerText = data.dns_host || ('appsmail._domainkey.' + domain);
                if (valEl) valEl.innerText = data.dns_record || '-';
            } catch (err) {
                if (valEl) valEl.innerText = 'Gagal memuat kunci DKIM.';
            }
        }

        function closeModal() {
            const m = document.getElementById('modal-dkim');
            if (m) {
                m.style.display = 'none';
                m.classList.remove('active');
            }
        }

        function openPassModal(id, email) {
            currentPassAccId = id;
            document.getElementById('pass-modal-email').innerText = 'Password Baru untuk ' + email;
            document.getElementById('modal-pass').style.display = 'flex';
        }

        function closePassModal() {
            document.getElementById('modal-pass').style.display = 'none';
            document.getElementById('pass-new').value = '';
        }

        async function submitPasswordChange() {
            const pass = document.getElementById('pass-new').value;
            if (!pass) return alert('Password tidak boleh kosong');
            const res = await fetch('/api/accounts/password', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({id: currentPassAccId, password: pass})
            });
            if (res.ok) {
                alert('Password berhasil diperbarui');
                closePassModal();
            } else {
                alert('Gagal memperbarui password');
            }
        }

        async function checkDNS() {
            const dom = document.getElementById('dns-check-domain').value;
            if (!dom) return alert('Pilih domain terlebih dahulu');
            const res = await fetch('/api/dns/check?domain=' + dom);
            const data = await res.json();
            document.getElementById('dns-results').style.display = 'block';
            const tbody = document.getElementById('table-dns-results');
            tbody.innerHTML = '';

            const mxBadge = data.mx_valid ? '<span class="tag-status tag-active">✔ Valid</span>' : '<span class="tag-status tag-inactive">✖ Belum Terpasang</span>';
            tbody.innerHTML += '<tr><td><strong>MX Record</strong></td><td>' + mxBadge + '</td><td><code>' + (data.mx_records ? data.mx_records.join(', ') : 'None') + '</code></td><td>Host: <code>@</code> | Target: <code>mail.elsw-studio.my.id</code> (Pri: 10)</td></tr>';

            const spfBadge = data.spf_valid ? '<span class="tag-status tag-active">✔ Valid</span>' : '<span class="tag-status tag-inactive">✖ Belum Terpasang</span>';
            tbody.innerHTML += '<tr><td><strong>SPF Record</strong></td><td>' + spfBadge + '</td><td><code>' + (data.spf_record || 'None') + '</code></td><td>Host: <code>@</code> | TXT: <code>v=spf1 +mx +ip4:103.147.157.37 ~all</code></td></tr>';

            const dkimBadge = data.dkim_valid ? '<span class="tag-status tag-active">✔ Valid</span>' : '<span class="tag-status tag-inactive">✖ Belum Terpasang</span>';
            tbody.innerHTML += '<tr><td><strong>DKIM Record</strong></td><td>' + dkimBadge + '</td><td><code>' + (data.dkim_record ? data.dkim_record.substring(0, 35) + '...' : 'None') + '</code></td><td>Host: <code>appsmail._domainkey</code> | Klik tombol "DKIM TXT" di menu Domains</td></tr>';

            const dmarcBadge = data.dmarc_valid ? '<span class="tag-status tag-active">✔ Valid</span>' : '<span class="tag-status tag-inactive">✖ Belum Terpasang</span>';
            tbody.innerHTML += '<tr><td><strong>DMARC Record</strong></td><td>' + dmarcBadge + '</td><td><code>' + (data.dmarc_record || 'None') + '</code></td><td>Host: <code>_dmarc</code> | TXT: <code>v=DMARC1; p=none; sp=none;</code></td></tr>';
        }

        async function fetchQueue() {
            const res = await fetch('/api/queue');
            const data = await res.json() || [];
            const tbody = document.getElementById('table-queue');
            tbody.innerHTML = '';
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--success); padding: 26px;">✔ Antrean email bersih. Seluruh pesan telah terkirim!</td></tr>';
                return;
            }
            data.forEach(q => {
                tbody.innerHTML += '<tr><td><code>' + q.id + '</code></td><td>' + q.size + '</td><td>' + q.date + '</td><td>' + q.sender + '</td><td>' + q.recipient + '</td><td style="color: var(--danger);">' + (q.reason || '-') + '</td><td><button class="btn btn-danger btn-sm" onclick="deleteQueue(\'' + q.id + '\')">Hapus</button></td></tr>';
            });
        }

        async function flushQueue() {
            const res = await fetch('/api/queue/flush', {method: 'POST'});
            if (res.ok) {
                alert('Proses flush antrean pengiriman berhasil dipicu');
                fetchQueue();
            }
        }

        async function deleteQueue(id) {
            if (!confirm('Hapus antrean ' + id + '?')) return;
            const res = await fetch('/api/queue/delete?id=' + id, {method: 'POST'});
            if (res.ok) {
                fetchQueue();
                fetchStats();
            }
        }

        async function fetchLogs() {
            const box = document.getElementById('log-box');
            box.innerText = 'Mengambil log terbaru dari journalctl...';
            const res = await fetch('/api/logs?lines=100');
            const data = await res.json();
            box.innerText = data.logs || 'Belum ada log.';
            box.scrollTop = box.scrollHeight;
        }

        async function sendTestEmail(e) {
            e.preventDefault();
            const from = document.getElementById('wm-from').value;
            const to = document.getElementById('wm-to').value;
            const subject = document.getElementById('wm-subj').value;
            const body = document.getElementById('wm-body').value;

            const res = await fetch('/api/webmail/send', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({from, to, subject, body})
            });

            if (res.ok) {
                alert('✔ Email berhasil dikirimkan ke MTA Postfix! Cek Mail Queue atau log untuk status pengiriman.');
                fetchStats();
            } else {
                const err = await res.json();
                alert('Gagal mengirim email: ' + err.error);
            }
        }

        let currentInboxMessages = [];

        async function fetchInbox() {
            const sel = document.getElementById('wm-inbox-email');
            const email = sel ? sel.value : '';
            if (!email) return;
            const box = document.getElementById('inbox-list');
            box.innerHTML = '<div style="padding: 24px; text-align: center; color: var(--text-muted);"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg><div style="margin-top: 8px; font-size: 13px;">Memeriksa folder Maildir...</div></div>';

            try {
                const res = await fetchWithTimeout('/api/webmail/inbox?email=' + encodeURIComponent(email), { timeout: 4500 });
                currentInboxMessages = await res.json() || [];

                if (currentInboxMessages.length === 0) {
                    box.innerHTML = '<div style="padding: 36px 20px; text-align: center; color: var(--text-muted); font-size: 13.5px;"><svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="1.8" style="margin-bottom: 8px;"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg><br>Kotak masuk kosong. Belum ada email untuk <strong>' + email + '</strong></div>';
                    return;
                }

                box.innerHTML = '';
                currentInboxMessages.forEach((m, idx) => {
                    const subj = m.subject || '(Tanpa Judul)';
                    const sender = m.from || '-';
                    const preview = m.snippet || m.body || '-';
                    box.innerHTML += '<div class="inbox-item" onclick="openInboxMessage(' + idx + ')">' +
                        '<div style="display: flex; align-items: flex-start; gap: 12px; flex-grow: 1; min-width: 0;">' +
                            '<div style="width: 34px; height: 34px; border-radius: 8px; background: #eff6ff; color: #2563eb; display: flex; align-items: center; justify-content: center; flex-shrink: 0; margin-top: 2px;">' +
                                '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>' +
                            '</div>' +
                            '<div style="flex-grow: 1; min-width: 0;">' +
                                '<div style="display: flex; justify-content: space-between; align-items: baseline; gap: 8px;">' +
                                    '<div style="font-size: 14px; font-weight: 700; color: var(--text-title); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">' + subj + '</div>' +
                                    '<div style="font-size: 11.5px; color: var(--text-muted); flex-shrink: 0;">' + (m.date || '') + '</div>' +
                                '</div>' +
                                '<div style="font-size: 12.5px; color: #334155; margin-top: 2px; font-weight: 600;">' + sender + '</div>' +
                                '<div style="font-size: 12px; color: var(--text-muted); margin-top: 3px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">' + preview + '</div>' +
                            '</div>' +
                        '</div>' +
                        '<button class="btn btn-primary btn-sm" style="margin-left: 12px; flex-shrink: 0;" onclick="event.stopPropagation(); openInboxMessage(' + idx + ')">' +
                            '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>' +
                            '<span>Baca</span>' +
                        '</button>' +
                    '</div>';
                });
            } catch(e) {
                box.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--danger);">Gagal memuat inbox: ' + e + '</div>';
            }
        }

        function openInboxMessage(idx) {
            const m = currentInboxMessages[idx];
            if (!m) return;

            window.currentReadingMsg = m;
            document.getElementById('read-subject').innerText = m.subject || '(Tanpa Judul)';
            document.getElementById('read-from').innerText = m.from || '-';
            const emailSel = document.getElementById('wm-inbox-email');
            document.getElementById('read-to').innerText = m.to || (emailSel ? emailSel.value : '-');
            document.getElementById('read-date').innerText = m.date || '-';

            let fromStr = m.from || 'U';
            let initial = fromStr.trim().charAt(0).toUpperCase();
            if (initial === '<' || initial === '"') initial = 'U';
            document.getElementById('read-avatar').innerText = initial || '@';

            let bodyContent = m.body || m.snippet || '';
            if (!bodyContent.trim()) {
                bodyContent = '(Email tidak berisi teks plain atau hanya berisi lampiran)';
            }
            document.getElementById('read-body').innerText = bodyContent;
            document.getElementById('modal-read-email').style.display = 'flex';
        }

        function replyCurrentEmail() {
            if (!window.currentReadingMsg) return;
            const m = window.currentReadingMsg;
            closeReadModal();
            nav('webmail');

            let sender = m.from || '';
            const match = sender.match(/<([^>]+)>/);
            document.getElementById('wm-to').value = match ? match[1] : sender;

            let sub = m.subject || '';
            if (!sub.toLowerCase().startsWith('re:')) {
                sub = 'Re: ' + sub;
            }
            document.getElementById('wm-subj').value = sub;
            document.getElementById('wm-body').value = "\n\n--- Pesan Asli ---\nDari: " + m.from + "\nTanggal: " + m.date + "\n\n" + (m.body || m.snippet || '');
            document.getElementById('wm-body').focus();
        }

        function closeReadModal() {
            document.getElementById('modal-read-email').style.display = 'none';
        }

        let currentTransactionsList = [];

        async function fetchTransactions() {
            const table = document.getElementById('table-transactions');
            if (table) {
                table.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 32px; color: var(--text-muted); font-size: 13.5px;"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2.5" class="spin" style="display:inline-block; vertical-align:middle; margin-right:10px;"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg><span>Memuat riwayat transaksi email...</span></td></tr>';
            }

            try {
                const sRes = await fetch('/api/transactions/stats');
                if (sRes.ok) {
                    const stats = await sRes.json();
                    if (document.getElementById('kpi-tx-total')) document.getElementById('kpi-tx-total').innerText = stats.total_month || 0;
                    if (document.getElementById('kpi-tx-delivered')) document.getElementById('kpi-tx-delivered').innerText = (stats.total_delivered || 0) + (stats.total_sent || 0);
                    if (document.getElementById('kpi-tx-delivered-sub')) document.getElementById('kpi-tx-delivered-sub').innerText = (stats.total_sent || 0) + ' Terkirim | ' + (stats.total_delivered || 0) + ' Diterima';
                    if (document.getElementById('kpi-tx-rejected')) document.getElementById('kpi-tx-rejected').innerText = (stats.total_rejected || 0) + (stats.total_spam || 0);
                    if (document.getElementById('kpi-tx-rejected-sub')) document.getElementById('kpi-tx-rejected-sub').innerText = (stats.total_spam || 0) + ' Spam | ' + (stats.total_rejected || 0) + ' Rejected';
                    
                    const archFiles = stats.archived_files || 0;
                    if (document.getElementById('kpi-tx-archives')) document.getElementById('kpi-tx-archives').innerText = archFiles + ' File';
                    let sizeStr = '0 KB';
                    if (stats.archived_bytes > 1024*1024) {
                        sizeStr = (stats.archived_bytes / (1024*1024)).toFixed(2) + ' MB';
                    } else if (stats.archived_bytes > 0) {
                        sizeStr = (stats.archived_bytes / 1024).toFixed(1) + ' KB';
                    }
                    if (document.getElementById('kpi-tx-archives-size')) document.getElementById('kpi-tx-archives-size').innerText = sizeStr + ' dikompresi (.json.gz)';

                    const archBox = document.getElementById('archives-list-box');
                    if (archBox) {
                        if (stats.archives && stats.archives.length > 0) {
                            let archHtml = '';
                            stats.archives.forEach(function(a) {
                                archHtml += '<div style="background: #f8fafc; border: 1px solid var(--border); border-radius: 9px; padding: 12px 14px; display: flex; align-items: center; justify-content: space-between;">' +
                                    '<div>' +
                                        '<div style="font-weight: 700; font-size: 13px; color: #1e3a8a; font-family: monospace;">' + escapeHtml(a.filename) + '</div>' +
                                        '<div style="font-size: 11.5px; color: var(--text-muted); margin-top: 2px;">Diperbarui: ' + escapeHtml(a.mod_time) + '</div>' +
                                    '</div>' +
                                    '<span style="padding: 3px 8px; background: #e0f2fe; color: #0284c7; border-radius: 6px; font-weight: 700; font-size: 11.5px;">' + escapeHtml(a.size_kb) + '</span>' +
                                '</div>';
                            });
                            archBox.innerHTML = archHtml;
                        } else {
                            archBox.innerHTML = '<div style="font-size: 13px; color: var(--text-muted); padding: 12px; background: #fafafa; border-radius: 8px;">Belum ada file arsip yang dibuat (seluruh transaksi masih dalam rentang 30 hari).</div>';
                        }
                    }
                }
            } catch(e) {
                console.error('Error fetching transaction stats:', e);
            }

            try {
                const search = (document.getElementById('tx-search') ? document.getElementById('tx-search').value : '').trim();
                const status = document.getElementById('tx-status') ? document.getElementById('tx-status').value : 'ALL';
                const direction = document.getElementById('tx-direction') ? document.getElementById('tx-direction').value : 'ALL';
                const days = document.getElementById('tx-days') ? document.getElementById('tx-days').value : '30';

                const url = '/api/transactions?days=' + encodeURIComponent(days) +
                    '&status=' + encodeURIComponent(status) +
                    '&direction=' + encodeURIComponent(direction) +
                    '&search=' + encodeURIComponent(search) +
                    '&limit=100';

                const res = await fetch(url);
                if (!res.ok) throw new Error('HTTP ' + res.status);
                const data = await res.json();
                currentTransactionsList = data || [];

                const subtitle = document.getElementById('tx-table-subtitle');
                if (subtitle) {
                    subtitle.innerText = 'Menampilkan ' + currentTransactionsList.length + ' transaksi (Maksimal data aktif ' + days + ' hari terakhir)';
                }

                if (!table) return;
                if (currentTransactionsList.length === 0) {
                    table.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 36px; color: var(--text-muted); font-size: 13.5px;">' +
                        'Tidak ada data transaksi email yang cocok dengan filter (rentang maks. ' + days + ' hari).' +
                    '</td></tr>';
                    return;
                }

                let rowsHtml = '';
                currentTransactionsList.forEach(function(tx, idx) {
                    let stBadge = '<span class="tag-status tag-active">' + escapeHtml(tx.status) + '</span>';
                    if (tx.status === 'REJECTED') {
                        stBadge = '<span class="tag-status tag-inactive" style="background:#fef2f2; color:#dc2626; border:1px solid #fecaca;">REJECTED</span>';
                    } else if (tx.status === 'SPAM') {
                        stBadge = '<span class="tag-status" style="background:#fffbeb; color:#d97706; border:1px solid #fde68a;">SPAM</span>';
                    } else if (tx.status === 'GREYLISTED' || tx.status === 'DEFERRED') {
                        stBadge = '<span class="tag-status" style="background:#eff6ff; color:#2563eb; border:1px solid #bfdbfe;">' + escapeHtml(tx.status) + '</span>';
                    }

                    let dirBadge = '<span style="font-size: 11px; padding: 2px 7px; border-radius: 5px; background: #e0f2fe; color: #0369a1; font-weight: 700;">INBOUND</span>';
                    if (tx.direction === 'OUTBOUND') {
                        dirBadge = '<span style="font-size: 11px; padding: 2px 7px; border-radius: 5px; background: #f3e8ff; color: #7e22ce; font-weight: 700;">OUTBOUND</span>';
                    }

                    let sizeStr = tx.size_bytes + ' B';
                    if (tx.size_bytes > 1024 * 1024) {
                        sizeStr = (tx.size_bytes / (1024*1024)).toFixed(2) + ' MB';
                    } else if (tx.size_bytes > 1024) {
                        sizeStr = (tx.size_bytes / 1024).toFixed(1) + ' KB';
                    }

                    let scoreColor = '#059669';
                    if (tx.spam_score >= 15.0) scoreColor = '#dc2626';
                    else if (tx.spam_score >= 6.0) scoreColor = '#d97706';

                    let subj = tx.subject || '(Tanpa Judul)';
                    if (subj.length > 40) subj = subj.substring(0, 40) + '...';

                    rowsHtml += '<tr>' +
                        '<td style="white-space: nowrap; font-size: 12.5px; font-weight: 600; color: var(--text-title);">' + escapeHtml(tx.timestamp) + '</td>' +
                        '<td>' + dirBadge + '</td>' +
                        '<td style="max-width: 170px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12.5px;" title="' + escapeHtml(tx.sender) + '">' + escapeHtml(tx.sender) + '</td>' +
                        '<td style="max-width: 170px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12.5px;" title="' + escapeHtml(tx.recipient) + '">' + escapeHtml(tx.recipient) + '</td>' +
                        '<td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12.5px; font-weight: 500;" title="' + escapeHtml(tx.subject) + '">' + escapeHtml(subj) + '</td>' +
                        '<td style="white-space: nowrap; font-size: 12px; color: var(--text-muted);">' + escapeHtml(sizeStr) + '</td>' +
                        '<td style="white-space: nowrap; font-weight: 700; color: ' + scoreColor + '; font-size: 12.5px;">' + tx.spam_score.toFixed(1) + '</td>' +
                        '<td>' + stBadge + '</td>' +
                        '<td style="text-align: center; white-space: nowrap;">' +
                            '<button class="btn btn-outline btn-sm" onclick="openTxDetail(' + idx + ')" style="padding: 4px 10px; font-size: 11.5px;">' +
                                '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>' +
                                '<span>Detail</span>' +
                            '</button>' +
                        '</td>' +
                    '</tr>';
                });
                table.innerHTML = rowsHtml;

            } catch(e) {
                console.error('Error fetching transactions:', e);
                if (table) {
                    table.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 24px; color: var(--danger);">Gagal memuat log transaksi: ' + escapeHtml(e.message || e) + '</td></tr>';
                }
            }
        }

        function openTxDetail(idx) {
            const tx = currentTransactionsList[idx];
            if (!tx) return;

            document.getElementById('modal-tx-id').innerText = 'ID Transaksi: #' + tx.id + ' | Client IP: ' + (tx.client_ip || '127.0.0.1');
            document.getElementById('modal-tx-time').innerText = tx.timestamp + ' WIB';
            document.getElementById('modal-tx-sender').innerText = tx.sender;
            document.getElementById('modal-tx-rcpt').innerText = tx.recipient;
            document.getElementById('modal-tx-subject').innerText = tx.subject || '(Tanpa Judul)';
            document.getElementById('modal-tx-ip').innerText = tx.client_ip || '127.0.0.1';
            document.getElementById('modal-tx-score').innerText = tx.spam_score.toFixed(1);
            document.getElementById('modal-tx-msgid').innerText = tx.message_id || '(Tidak ada Message-ID)';

            let sizeStr = tx.size_bytes + ' Bytes';
            if (tx.size_bytes > 1024*1024) sizeStr = (tx.size_bytes / (1024*1024)).toFixed(2) + ' MB';
            else if (tx.size_bytes > 1024) sizeStr = (tx.size_bytes / 1024).toFixed(1) + ' KB';
            document.getElementById('modal-tx-size').innerText = sizeStr;

            let stWrap = '<span class="tag-status tag-active">' + escapeHtml(tx.status) + '</span>';
            if (tx.status === 'REJECTED') stWrap = '<span class="tag-status tag-inactive" style="background:#fef2f2; color:#dc2626; border:1px solid #fecaca;">REJECTED</span>';
            else if (tx.status === 'SPAM') stWrap = '<span class="tag-status" style="background:#fffbeb; color:#d97706; border:1px solid #fde68a;">SPAM</span>';
            
            let dirBadge = '<span style="font-size: 11px; padding: 2px 7px; border-radius: 5px; background: #e0f2fe; color: #0369a1; font-weight: 700;">INBOUND</span>';
            if (tx.direction === 'OUTBOUND') dirBadge = '<span style="font-size: 11px; padding: 2px 7px; border-radius: 5px; background: #f3e8ff; color: #7e22ce; font-weight: 700;">OUTBOUND</span>';
            document.getElementById('modal-tx-status-wrap').innerHTML = stWrap + ' ' + dirBadge;

            let detailsPretty = tx.details || '';
            try {
                const parsed = JSON.parse(tx.details);
                detailsPretty = JSON.stringify(parsed, null, 2);
            } catch(e) {}
            document.getElementById('modal-tx-details').innerText = detailsPretty || '(Tidak ada data detail tambahan)';

            document.getElementById('modal-tx-detail').style.display = 'flex';
        }

        function closeTxDetailModal() {
            const m = document.getElementById('modal-tx-detail');
            if (m) m.style.display = 'none';
        }

        function resetTxFilters() {
            if (document.getElementById('tx-search')) document.getElementById('tx-search').value = '';
            if (document.getElementById('tx-status')) document.getElementById('tx-status').value = 'ALL';
            if (document.getElementById('tx-direction')) document.getElementById('tx-direction').value = 'ALL';
            if (document.getElementById('tx-days')) document.getElementById('tx-days').value = '30';
            fetchTransactions();
        }

        async function triggerManualArchive() {
            const btn = document.getElementById('btn-manual-archive');
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<span class="spin">🔄</span> Mengompresi & Mengarsip...';
            }
            try {
                const res = await fetch('/api/transactions/archive', { method: 'POST' });
                const data = await res.json();
                alert(data.message || 'Proses arsip selesai!');
                fetchTransactions();
            } catch(e) {
                alert('Gagal menjalankan arsip: ' + e);
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg><span>Jalankan Arsip Sekarang</span>';
                }
            }
        }

        // ==================== USER MANAGEMENT & 2FA SCRIPT ====================
        let currentAdminUser = null;
        let cachedOTPData = null;
        let dashboardUsersCache = [];

        async function fetchCurrentUser() {
            try {
                const res = await fetch('/api/auth/me');
                if (res.status === 401) {
                    window.location.href = '/';
                    return;
                }
                const data = await res.json();
                if (data.user) {
                    currentAdminUser = data.user;
                    const u = data.user;
                    const navUser = document.getElementById('nav-username');
                    const navRole = document.getElementById('nav-user-role');
                    const navAvatar = document.getElementById('nav-user-avatar');
                    if (navUser) navUser.textContent = u.username;
                    if (navRole) navRole.textContent = u.role === 'superadmin' ? 'Superadmin' : 'Administrator';
                    if (navAvatar && u.username) {
                        navAvatar.textContent = u.username.substring(0, 2).toUpperCase();
                    }
                }
            } catch (err) {
                console.error('fetchCurrentUser error:', err);
            }
        }

        async function fetchDashboardUsers() {
            const tbody = document.getElementById('table-users');
            if (!tbody) return;
            try {
                const res = await fetch('/api/dashboard-users');
                if (res.status === 401) {
                    window.location.href = '/';
                    return;
                }
                const data = await res.json();
                const users = data.users || [];
                dashboardUsersCache = users;
                const sessionsCount = data.active_sessions || 0;

                const kpiTotal = document.getElementById('kpi-users-total');
                const kpiSuper = document.getElementById('kpi-users-super');
                const kpiOtp = document.getElementById('kpi-users-otp');
                const kpiSessions = document.getElementById('kpi-users-sessions');

                let superCount = 0;
                let otpCount = 0;
                users.forEach(function(u) {
                    if (u.role === 'superadmin') superCount++;
                    if (u.otp_enabled) otpCount++;
                });

                if (kpiTotal) kpiTotal.textContent = users.length;
                if (kpiSuper) kpiSuper.textContent = superCount;
                if (kpiOtp) {
                    kpiOtp.textContent = otpCount + ' / ' + users.length;
                    kpiOtp.style.color = otpCount > 0 ? 'var(--success)' : 'var(--text-title)';
                }
                if (kpiSessions) kpiSessions.textContent = sessionsCount;

                if (users.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:24px; color:var(--text-muted);">Belum ada administrator terdaftar.</td></tr>';
                    return;
                }

                tbody.innerHTML = users.map(function(u) {
                    const initials = (u.username || 'AD').substring(0, 2).toUpperCase();
                    const isSelf = currentAdminUser && currentAdminUser.id === u.id;
                    const roleBadge = u.role === 'superadmin' 
                        ? '<span class="status-pill" style="background:#f3e8ff; color:#7e22ce; border-color:#d8b4fe;"><span class="status-dot" style="background:#a855f7;"></span> Superadmin</span>'
                        : '<span class="status-pill" style="background:#eff6ff; color:#1d4ed8; border-color:#bfdbfe;"><span class="status-dot" style="background:#3b82f6;"></span> Administrator</span>';
                    
                    const otpBadge = u.otp_enabled
                        ? '<span class="status-pill" style="background:#ecfdf5; color:#065f46; border-color:#a7f3d0;"><span class="status-dot" style="background:#10b981;"></span> OTP Aktif</span>'
                        : '<span class="status-pill" style="background:#f1f5f9; color:#475569; border-color:#cbd5e1;"><span class="status-dot" style="background:#94a3b8;"></span> Nonaktif (Default)</span>';

                    let lastLoginStr = 'Belum pernah login';
                    if (u.last_login) {
                        try {
                            const d = new Date(u.last_login);
                            lastLoginStr = d.toLocaleDateString('id-ID', { day: '2-digit', month: 'short', year: 'numeric' }) + ' ' + d.toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit' });
                        } catch (e) {
                            lastLoginStr = u.last_login;
                        }
                    }

                    let createdStr = '-';
                    if (u.created_at) {
                        try {
                            const cd = new Date(u.created_at);
                            createdStr = cd.toLocaleDateString('id-ID', { day: '2-digit', month: 'short', year: 'numeric' });
                        } catch (e) {
                            createdStr = u.created_at;
                        }
                    }

                    let actionsHtml = '<div style="display:flex; justify-content:flex-end; gap:6px;">';
                    actionsHtml += '<button class="btn btn-outline btn-sm" onclick="openOTPModal(' + u.id + ')" style="padding:4px 10px; font-size:12px;" title="Konfigurasi 2FA / OTP">Kelola OTP</button>';
                    actionsHtml += '<button class="btn btn-outline btn-sm" onclick="openUserPassModal(' + u.id + ')" style="padding:4px 10px; font-size:12px;" title="Reset Password">Sandi</button>';
                    
                    if (!isSelf) {
                        actionsHtml += '<button class="btn btn-danger btn-sm" onclick="deleteDashboardUser(' + u.id + ')" style="padding:4px 10px; font-size:12px;" title="Hapus Administrator">Hapus</button>';
                    } else {
                        actionsHtml += '<span style="font-size:11px; color:#94a3b8; padding:4px 6px;">(Akun Anda)</span>';
                    }
                    actionsHtml += '</div>';

                    return '<tr>' +
                        '<td>' +
                            '<div style="display:flex; align-items:center; gap:10px;">' +
                                '<div style="width:32px; height:32px; border-radius:50%; background:linear-gradient(135deg, #2563eb, #6366f1); color:#fff; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:12px;">' + initials + '</div>' +
                                '<div>' +
                                    '<div style="font-weight:600; color:var(--text-title);">' + escapeHtml(u.username) + '</div>' +
                                    '<div style="font-size:12px; color:var(--text-muted);">' + escapeHtml(u.email) + '</div>' +
                                '</div>' +
                            '</div>' +
                        '</td>' +
                        '<td>' + roleBadge + '</td>' +
                        '<td>' + otpBadge + '</td>' +
                        '<td style="font-size:13px; color:var(--text-body);">' + lastLoginStr + '</td>' +
                        '<td style="font-size:13px; color:var(--text-muted);">' + createdStr + '</td>' +
                        '<td style="text-align:right;">' + actionsHtml + '</td>' +
                    '</tr>';
                }).join('');

            } catch (err) {
                console.error('fetchDashboardUsers error:', err);
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:24px; color:var(--danger);">Gagal memuat data administrator.</td></tr>';
            }
        }

        function openAddUserModal() {
            document.getElementById('add-user-username').value = '';
            document.getElementById('add-user-email').value = '';
            document.getElementById('add-user-password').value = '';
            document.getElementById('add-user-role').value = 'admin';
            const m = document.getElementById('modal-add-user');
            if (m) {
                m.style.display = 'flex';
                m.classList.add('active');
            }
            const inp = document.getElementById('add-user-username');
            if (inp) inp.focus();
        }

        function closeAddUserModal() {
            const m = document.getElementById('modal-add-user');
            if (m) {
                m.style.display = 'none';
                m.classList.remove('active');
            }
        }

        async function submitAddUser() {
            const u = document.getElementById('add-user-username').value.trim();
            const e = document.getElementById('add-user-email').value.trim();
            const p = document.getElementById('add-user-password').value;
            const r = document.getElementById('add-user-role').value;

            if (!u || !e || !p) {
                alert('Semua kolom wajib diisi!');
                return;
            }
            if (p.length < 6) {
                alert('Kata sandi minimal 6 karakter.');
                return;
            }

            try {
                const res = await fetch('/api/dashboard-users', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: u, email: e, password: p, role: r })
                });
                const data = await res.json();
                if (!res.ok) {
                    alert(data.error || 'Gagal menambahkan administrator.');
                    return;
                }
                alert('Administrator ' + u + ' berhasil ditambahkan! (OTP default: Nonaktif)');
                closeAddUserModal();
                fetchDashboardUsers();
            } catch (err) {
                alert('Gagal menghubungi server.');
            }
        }

        function openUserPassModal(id) {
            const u = (dashboardUsersCache || []).find(function(x) { return x.id === id; });
            const username = u ? u.username : ('User #' + id);
            document.getElementById('reset-user-id').value = id;
            document.getElementById('reset-user-target').textContent = username;
            document.getElementById('reset-user-newpass').value = '';
            document.getElementById('reset-user-confirmpass').value = '';
            const m = document.getElementById('modal-user-pass');
            if (m) {
                m.style.display = 'flex';
                m.classList.add('active');
            }
            const inp = document.getElementById('reset-user-newpass');
            if (inp) inp.focus();
        }

        function closeUserPassModal() {
            const m = document.getElementById('modal-user-pass');
            if (m) {
                m.style.display = 'none';
                m.classList.remove('active');
            }
        }

        async function submitUserPass() {
            const id = parseInt(document.getElementById('reset-user-id').value, 10);
            const p1 = document.getElementById('reset-user-newpass').value;
            const p2 = document.getElementById('reset-user-confirmpass').value;

            if (!p1) {
                alert('Masukkan kata sandi baru.');
                return;
            }
            if (p1.length < 6) {
                alert('Kata sandi minimal 6 karakter.');
                return;
            }
            if (p1 !== p2) {
                alert('Konfirmasi kata sandi tidak cocok.');
                return;
            }

            try {
                const res = await fetch('/api/dashboard-users/password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user_id: id, password: p1 })
                });
                const data = await res.json();
                if (!res.ok) {
                    alert(data.error || 'Gagal memperbarui kata sandi.');
                    return;
                }
                alert('Kata sandi berhasil diperbarui!');
                closeUserPassModal();
            } catch (err) {
                alert('Gagal menghubungi server.');
            }
        }

        async function openOTPModal(id) {
            const u = (dashboardUsersCache || []).find(function(x) { return x.id === id; });
            const username = u ? u.username : ('User #' + id);
            document.getElementById('otp-modal-user-id').value = id;
            document.getElementById('otp-modal-target').textContent = username;
            document.getElementById('otp-confirm-code').value = '';

            try {
                const res = await fetch('/api/auth/otp/setup?user_id=' + id);
                const data = await res.json();
                if (!res.ok) {
                    alert(data.error || 'Gagal memuat konfigurasi OTP.');
                    return;
                }
                cachedOTPData = data;
                document.getElementById('otp-secret-display').textContent = data.secret || '-';

                if (data.otp_enabled) {
                    document.getElementById('otp-state-active').style.display = 'block';
                    document.getElementById('otp-state-inactive').style.display = 'none';
                } else {
                    document.getElementById('otp-state-active').style.display = 'none';
                    document.getElementById('otp-state-inactive').style.display = 'block';
                }
                const m = document.getElementById('modal-user-otp');
                if (m) {
                    m.style.display = 'flex';
                    m.classList.add('active');
                }
            } catch (err) {
                alert('Gagal menghubungi server.');
            }
        }

        function closeOTPModal() {
            const m = document.getElementById('modal-user-otp');
            if (m) {
                m.style.display = 'none';
                m.classList.remove('active');
            }
        }

        function copyOTPSecret() {
            if (!cachedOTPData || !cachedOTPData.secret) return;
            navigator.clipboard.writeText(cachedOTPData.secret).then(function() {
                const btn = document.getElementById('btn-copy-secret');
                const orig = btn.textContent;
                btn.textContent = 'Tersalin!';
                setTimeout(function() { btn.textContent = orig; }, 1500);
            });
        }

        async function submitEnableOTP() {
            const id = parseInt(document.getElementById('otp-modal-user-id').value, 10);
            const code = document.getElementById('otp-confirm-code').value.trim();
            if (!code || code.length !== 6) {
                alert('Masukkan 6 digit kode dari aplikasi Authenticator untuk verifikasi aktivasi.');
                return;
            }

            try {
                const res = await fetch('/api/auth/otp/toggle', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user_id: id, enable: true, code: code })
                });
                const data = await res.json();
                if (!res.ok) {
                    alert(data.error || 'Gagal mengaktifkan OTP.');
                    return;
                }
                alert('Autentikasi Dua Langkah (2FA) berhasil DIAKTIFKAN untuk akun ini!');
                closeOTPModal();
                fetchDashboardUsers();
                fetchCurrentUser();
            } catch (err) {
                alert('Gagal menghubungi server.');
            }
        }

        async function disableOTP() {
            const id = parseInt(document.getElementById('otp-modal-user-id').value, 10);
            if (!confirm('Apakah Anda yakin ingin menonaktifkan 2FA untuk akun ini? Status OTP akan kembali ke Nonaktif (Default).')) {
                return;
            }

            try {
                const res = await fetch('/api/auth/otp/toggle', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user_id: id, enable: false })
                });
                const data = await res.json();
                if (!res.ok) {
                    alert(data.error || 'Gagal menonaktifkan OTP.');
                    return;
                }
                alert('Autentikasi Dua Langkah (2FA) telah DINONAKTIFKAN.');
                closeOTPModal();
                fetchDashboardUsers();
                fetchCurrentUser();
            } catch (err) {
                alert('Gagal menghubungi server.');
            }
        }

        async function deleteDashboardUser(id) {
            const u = (dashboardUsersCache || []).find(function(x) { return x.id === id; });
            const username = u ? u.username : ('User #' + id);
            if (!confirm('Apakah Anda yakin ingin menghapus administrator "' + username + '"?')) {
                return;
            }

            try {
                const res = await fetch('/api/dashboard-users?id=' + id, { method: 'DELETE' });
                const data = await res.json();
                if (!res.ok) {
                    alert(data.error || 'Gagal menghapus administrator.');
                    return;
                }
                fetchDashboardUsers();
            } catch (err) {
                alert('Gagal menghubungi server.');
            }
        }

        function handleLogout() {
            if (confirm('Apakah Anda yakin ingin keluar dari dashboard EMXS?')) {
                fetch('/api/auth/logout', { method: 'POST' })
                    .then(function() {
                        window.location.href = '/';
                    })
                    .catch(function() {
                        window.location.href = '/';
                    });
            }
        }

        function refreshAll() {
            fetchStats();
            fetchDomains();
            fetchAccounts();
            fetchAliases();
            fetchCurrentUser();
            const txTab = document.getElementById('tab-transactions');
            if (txTab && txTab.classList.contains('active')) {
                fetchTransactions();
            }
            const uTab = document.getElementById('tab-users');
            if (uTab && uTab.classList.contains('active')) {
                fetchDashboardUsers();
            }
        }

        window.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeModal();
                closePassModal();
                closeReadModal();
                closeTxDetailModal();
                closeAddUserModal();
                closeUserPassModal();
                closeOTPModal();
            }
        });
        document.querySelectorAll('.modal').forEach(function(m) {
            m.addEventListener('click', function(e) {
                if (e.target === m) {
                    closeModal();
                    closePassModal();
                    closeReadModal();
                    closeTxDetailModal();
                    closeAddUserModal();
                    closeUserPassModal();
                    closeOTPModal();
                }
            });
        });

        refreshAll();
        setInterval(fetchStats, 10000);
    </script>
</body>
</html>`
	if configuredIP != "103.147.157.37" {
		html = strings.ReplaceAll(html, "103.147.157.37", configuredIP)
	}
	if configuredHost != "mail.elsw-studio.my.id" {
		html = strings.ReplaceAll(html, "mail.elsw-studio.my.id", configuredHost)
	}
	if configuredDomain != "elsw-studio.my.id" {
		html = strings.ReplaceAll(html, "elsw-studio.my.id", configuredDomain)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Write([]byte(html))
}
