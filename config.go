package adc

import (
	"crypto/x509"
	"time"
)

// SecurityType specifies the type of security to use when connecting to an Active Directory Server.
type SecurityType int

// Security will default to SecurityNone if not given.
const (
	SecurityNone SecurityType = iota
	SecurityTLS
	SecurityStartTLS
	SecurityInsecureTLS
	SecurityInsecureStartTLS
)

type Config struct {
	Server string `json:"server"`
	Port   int    `json:"port"`
	// RootCAs is a set of root certificate authorities to use when connecting to the server.
	RootCAs *x509.CertPool
	// Use insecure SSL connection.
	InsecureTLS bool `json:"insecure_tls"`
	// Time limit for requests.
	Timeout time.Duration
	// Base OU for search requests.
	SearchBase string       `json:"search_base"`
	Security   SecurityType `json:"security"`

	// Bind account info.
	Bind *BindAccount `json:"bind"`

	// Requests filters vars.
	Users *UsersConfigs `json:"users"`
	// Requests filters vars.
	Groups *GroupsConfigs `json:"groups"`
}

// Account attributes to authentificate in AD.
type BindAccount struct {
	DN       string `json:"dn"`
	Password string `json:"password"`
}

type UsersConfigs struct {
	// The ID attribute name for group.
	IdAttribute string `json:"id_attribute"`
	// User attributes for fetch from AD.
	Attributes []string `json:"attributes"`
	// Base OU to search users requests. Sets to Config.SearchBase if not provided.
	SearchBase string `json:"search_base"`
	// LDAP filter to get user by ID.
	FilterById string `json:"filter_by_id"`
	// LDAP filter to get user by DN.
	FilterByDn string `json:"filter_by_dn"`
	// LDAP filter to get user groups membership.
	FilterGroupsByDn string `json:"filter_groups_by_dn"`
}

type GroupsConfigs struct {
	// The ID attribute name for group.
	IdAttribute string `json:"id_attribute"`
	// Group attributes for fetch from AD.
	Attributes []string `json:"attributes"`
	// Base OU to search groups requests. Sets to Config.SearchBase if not provided.
	SearchBase string `json:"search_base"`
	// LDAP filter to get group by ID.
	FilterById string `json:"filter_by_id"`
	// LDAP filter to get group by DN.
	FilterByDn string `json:"filter_by_dn"`
	// LDAP filter to get group members.
	FilterMembersByDn string `json:"filter_members_by_dn"`
}

// Appends attributes to params in client config file.
//
// Deprecated: Use AppendUsersAttributes() instead. Will be removed soon.
func (cfg *Config) AppendUsesAttributes(attrs ...string) {
	cfg.AppendUsersAttributes(attrs...)
}

// Appends attributes to params in client config file.
func (cfg *Config) AppendUsersAttributes(attrs ...string) {
	cfg.Users.Attributes = append(cfg.Users.Attributes, attrs...)
}

// Appends attributes to params in client config file.
func (cfg *Config) AppendGroupsAttributes(attrs ...string) {
	cfg.Groups.Attributes = append(cfg.Groups.Attributes, attrs...)
}

func getDefaultConfig() *Config {
	return &Config{
		Timeout: 10 * time.Second,
		Users: &UsersConfigs{
			IdAttribute:      "sAMAccountName",
			Attributes:       []string{"sAMAccountName", "givenName", "sn", "mail"},
			FilterById:       "(&(objectClass=person)(sAMAccountName=%v))",
			FilterByDn:       "(&(objectClass=person)(distinguishedName=%v))",
			FilterGroupsByDn: "(&(objectClass=group)(member=%v))",
		},
		Groups: &GroupsConfigs{
			IdAttribute:       "sAMAccountName",
			Attributes:        []string{"sAMAccountName", "cn", "description"},
			FilterById:        "(&(objectClass=group)(sAMAccountName=%v))",
			FilterByDn:        "(&(objectClass=group)(distinguishedName=%v))",
			FilterMembersByDn: "(&(objectCategory=person)(memberOf=%v))",
		},
	}
}

func populateConfig(cfg *Config) *Config {
	result := getDefaultConfig()

	if cfg == nil {
		return result
	}

	result.Server = cfg.Server
	result.Port = cfg.Port
	result.Security = cfg.Security
	result.InsecureTLS = cfg.InsecureTLS
	result.SearchBase = cfg.SearchBase
	result.Users.SearchBase = cfg.SearchBase
	result.Groups.SearchBase = cfg.SearchBase
	result.Bind = cfg.Bind

	if cfg.Timeout != 0 {
		result.Timeout = cfg.Timeout
	}

	if cfg.Users != nil {
		result.Users.SearchBase = cfg.Users.SearchBase
		if len(cfg.Users.Attributes) > 0 {
			result.Users.Attributes = cfg.Users.Attributes
		}
		if cfg.Users.IdAttribute != "" {
			result.Users.IdAttribute = cfg.Users.IdAttribute
		}
		if cfg.Users.FilterById != "" {
			result.Users.FilterById = cfg.Users.FilterById
		}
		if cfg.Users.FilterByDn != "" {
			result.Users.FilterByDn = cfg.Users.FilterByDn
		}
		if cfg.Users.FilterGroupsByDn != "" {
			result.Users.FilterGroupsByDn = cfg.Users.FilterGroupsByDn
		}
	}

	if cfg.Groups != nil {
		result.Groups.SearchBase = cfg.Groups.SearchBase
		if len(cfg.Groups.Attributes) > 0 {
			result.Groups.Attributes = cfg.Groups.Attributes
		}
		if cfg.Groups.IdAttribute != "" {
			result.Groups.IdAttribute = cfg.Groups.IdAttribute
		}
		if cfg.Groups.FilterById != "" {
			result.Groups.FilterById = cfg.Groups.FilterById
		}
		if cfg.Groups.FilterByDn != "" {
			result.Groups.FilterByDn = cfg.Groups.FilterByDn
		}
		if cfg.Groups.FilterMembersByDn != "" {
			result.Groups.FilterMembersByDn = cfg.Groups.FilterMembersByDn
		}
	}

	return result
}
