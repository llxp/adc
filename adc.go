// Package adc provides basic client library for Active Directory.
package adc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Active Direcotry client.
type Client struct {
	Config *Config
	Ldap   ldap.Client
	logger Logger
}

// Creates new client and populate provided config and options.
func New(cfg *Config, opts ...Option) *Client {
	cl := &Client{
		Config: populateConfig(cfg),
		logger: newNopLogger(),
	}
	for _, opt := range opts {
		opt(cl)
	}
	return cl
}

type Option func(*Client)

// Specifies custom logger for client.
func WithLogger(l Logger) Option {
	return func(cl *Client) { cl.logger = l }
}

// Connects to AD server and store connection into client.
func (cl *Client) Connect() error {
	conn, err := cl.connect()
	if err != nil {
		return fmt.Errorf("Failed to connect: %w", err)
	}

	if cl.Config.Bind != nil {
		if err := conn.Bind(cl.Config.Bind.DN, cl.Config.Bind.Password); err != nil {
			return fmt.Errorf("Failed to bind: %w", err)
		}
	}

	cl.Ldap = conn

	return nil
}

// Connect returns an open connection to an Active Directory server or an error if one occurred.
func (cl *Client) connect() (ldap.Client, error) {
	server := cl.Config.Server
	port := cl.Config.Port
	switch cl.Config.Security {
	case SecurityNone:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		return conn, nil
	case SecurityTLS:
		conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", server, port), &tls.Config{ServerName: server, RootCAs: cl.Config.RootCAs})
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		return conn, nil
	case SecurityStartTLS:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		err = conn.StartTLS(&tls.Config{ServerName: server, RootCAs: cl.Config.RootCAs})
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		return conn, nil
	case SecurityInsecureTLS:
		conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", server, port), &tls.Config{ServerName: server, InsecureSkipVerify: true})
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		return conn, nil
	case SecurityInsecureStartTLS:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		err = conn.StartTLS(&tls.Config{ServerName: server, InsecureSkipVerify: true})
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		return conn, nil
	default:
		return nil, errors.New("Configuration error: invalid SecurityType")
	}
}

// Bind authenticates the connection with the given userPrincipalName and password
// and returns the result or an error if one occurred.
func (cl *Client) Bind(upn, password string) (bool, error) {
	if password == "" {
		return false, nil
	}

	err := cl.Ldap.Bind(upn, password)
	if err != nil {
		if e, ok := err.(*ldap.Error); ok {
			if e.ResultCode == ldap.LDAPResultInvalidCredentials {
				return false, nil
			}
		}
		return false, fmt.Errorf("Bind error (%s): %w", upn, err)
	}

	return true, nil
}

// func (cl *Client) connect() (ldap.Client, error) {
// 	var dialOpts []ldap.DialOpt
// 	if strings.HasPrefix(cl.Config.URL, "ldaps://") {
// 		dialOpts = append(
// 			dialOpts, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: cl.Config.InsecureTLS}),
// 		)
// 	}
// 	return ldap.DialURL(cl.Config.URL, dialOpts...)
// }

// Closes connection to AD.
func (cl *Client) Disconnect() error {
	if cl.Ldap == nil {
		return nil
	}
	return cl.Ldap.Close()
}

// Checks connections to AD and tries to reconnect if the connection is lost.
func (cl *Client) Reconnect(ctx context.Context, tickerDuration time.Duration, maxAttempts int) error {
	_, connErr := cl.searchEntry(&ldap.SearchRequest{
		BaseDN:       cl.Config.SearchBase,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		TimeLimit:    int(cl.Config.Timeout.Seconds()),
		Filter:       fmt.Sprintf(cl.Config.Users.FilterByDn, ldap.EscapeFilter(cl.Config.Bind.DN)),
		Attributes:   []string{cl.Config.Users.IdAttribute},
	})
	if connErr == nil {
		return nil
	}

	if tickerDuration == 0 {
		tickerDuration = 5 * time.Second
	}
	ticker := time.NewTicker(tickerDuration)
	defer ticker.Stop()

	if maxAttempts == 0 {
		maxAttempts = 2
	}

	attempt := 0
	for {
		select {
		case <-ticker.C:
			if attempt >= maxAttempts {
				return fmt.Errorf("failed after '%d' attempts. error: %s", attempt, connErr)
			}
			attempt++
			cl.logger.Debugf("Reconnecting to AD server. Attempt: %d", attempt)

			if err := cl.Disconnect(); err != nil {
				return fmt.Errorf("failed to disconnect from the server: %w", err)
			}

			if err := cl.Connect(); err == nil {
				cl.logger.Debug("Successfully reconneted to AD server")
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// SearchEntry Perfrom search for single ldap entry.
// Returns nil if no entries found.
// Returns 'ErrTooManyEntriesFound' error if entries more that one.
func (cl *Client) searchEntry(req *ldap.SearchRequest) (*ldap.Entry, error) {
	result, err := cl.Ldap.Search(req)
	if err != nil {
		return nil, err
	}
	if len(result.Entries) > 1 {
		return nil, errors.New("too many entries found")
	}
	if len(result.Entries) < 1 {
		return nil, nil
	}
	return result.Entries[0], nil
}

// SearchEntries Perfroms search for ldap entries.
func (cl *Client) searchEntries(req *ldap.SearchRequest) ([]*ldap.Entry, error) {
	result, err := cl.Ldap.Search(req)
	if err != nil {
		return nil, err
	}
	return result.Entries, nil
}

// Performs update for provided entry attribure by entry DN.
func (cl *Client) updateAttribute(dn string, attribute string, values []string) error {
	mr := ldap.NewModifyRequest(dn, nil)
	mr.Replace(attribute, values)
	return cl.Ldap.Modify(mr)
}

// Tries to authorise in AcitveDirecotry by provided DN and password and return error if failed.
// Use this method to check if user can be authenticated in AD.
func (cl *Client) CheckAuthByDN(dn, password string) error {
	conn, err := cl.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Bind(dn, password); err != nil {
		return err
	}
	return nil
}

func (cl *Client) createEntry(dn string, attributes []ldap.Attribute) error {
	cl.logger.Debugf("Creating '%s'; Attributes: %#v", dn, attributes)

	req := &ldap.AddRequest{
		DN:         dn,
		Attributes: attributes,
	}
	return cl.Ldap.Add(req)
}

func (cl *Client) deleteEntry(dn string) error {
	cl.logger.Debugf("Deleting: '%s'", dn)
	return cl.Ldap.Del(&ldap.DelRequest{DN: dn})
}
