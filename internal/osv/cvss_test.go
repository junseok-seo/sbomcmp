package osv

import "testing"

func TestBaseScore(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H":                    9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H":                    7.5,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N":                    6.1,
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H":                    7.8,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N":                    0,
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 9.3,
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N": 6.9,
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H":                          0,
		"garbage":                                                         0,
	}
	for vec, want := range cases {
		if got := BaseScore(vec); got != want {
			t.Errorf("%s: got %.1f want %.1f", vec, got, want)
		}
	}
	if Bucket(9.8) != "CRITICAL" || Bucket(7.5) != "HIGH" || Bucket(6.1) != "MEDIUM" || Bucket(2) != "LOW" || Bucket(0) != "UNKNOWN" {
		t.Fatal("bucket boundaries")
	}
}
