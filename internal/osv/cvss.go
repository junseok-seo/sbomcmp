package osv

import (
	"math"
	"strings"
)

// BaseScore computes the CVSS v3.0/v3.1 base score from a vector string.
// It returns 0 when the vector is not a parsable v3 vector (v2 and v4 are not
// scored here; callers fall back to database-provided severities).
func BaseScore(vec string) float64 {
	vec = strings.TrimSpace(vec)
	if !strings.HasPrefix(vec, "CVSS:3.") {
		return 0
	}
	m := map[string]string{}
	for _, kv := range strings.Split(vec, "/")[1:] {
		k, v, ok := strings.Cut(kv, ":")
		if ok {
			m[k] = v
		}
	}
	changed := m["S"] == "C"
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if changed {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if changed {
			pr = 0.5
		}
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, cok := cia[m["C"]]
	i, iok := cia[m["I"]]
	a, aok := cia[m["A"]]
	if av == 0 || ac == 0 || ui == 0 || pr == 0 || !cok || !iok || !aok {
		return 0
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}
	expl := 8.22 * av * ac * pr * ui
	if changed {
		return roundUp(math.Min(1.08*(impact+expl), 10))
	}
	return roundUp(math.Min(impact+expl, 10))
}

// roundUp implements the CVSS v3.1 Roundup function (one decimal, upwards).
func roundUp(x float64) float64 {
	n := int(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return (math.Floor(float64(n)/10000) + 1) / 10
}

// Bucket maps a score to CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN.
func Bucket(s float64) string {
	switch {
	case s >= 9:
		return "CRITICAL"
	case s >= 7:
		return "HIGH"
	case s >= 4:
		return "MEDIUM"
	case s > 0:
		return "LOW"
	}
	return "UNKNOWN"
}
