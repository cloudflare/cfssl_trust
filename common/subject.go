package common

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"
)

const DateFormat = "2006-01-02T15:04:05-0700"

func NameToString(name pkix.Name) string {
	var ns []string

	if name.CommonName != "" {
		ns = append(ns, name.CommonName)
	}

	for i := range name.Country {
		ns = append(ns, fmt.Sprintf("C=%s", name.Country[i]))
	}

	for i := range name.Organization {
		ns = append(ns, fmt.Sprintf("O=%s", name.Organization[i]))
	}

	for i := range name.OrganizationalUnit {
		ns = append(ns, fmt.Sprintf("OU=%s", name.OrganizationalUnit[i]))
	}

	for i := range name.Locality {
		ns = append(ns, fmt.Sprintf("L=%s", name.Locality[i]))
	}

	for i := range name.Province {
		ns = append(ns, fmt.Sprintf("ST=%s", name.Province[i]))
	}

	if len(ns) > 0 {
		return "/" + strings.Join(ns, "/")
	}

	return "*** no subject information ***"
}
