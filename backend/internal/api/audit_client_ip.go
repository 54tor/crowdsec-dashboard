package api

import (
	"net"
	"net/http"
	"net/netip"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
)

func auditClientIP(request *http.Request, trustedCIDRs []*net.IPNet) string {
	parsedAddress, _ := netip.ParseAddr(auth.ClientIP(request, trustedCIDRs))
	return audit.ClientIPText(parsedAddress)
}
