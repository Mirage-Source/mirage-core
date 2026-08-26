package validity

import (
	"reflect"
	"sort"
	"strconv"
	"testing"
)

func wordlist(n int, salt string) map[CredentialPair]struct{} {
	set := make(map[CredentialPair]struct{}, n)
	for i := 0; i < n; i++ {
		s := strconv.Itoa(i)
		set[CredentialPair{
			Username:   "user" + s + salt,
			Credential: "pass" + s + salt,
		}] = struct{}{}
	}
	return set
}

func TestDivisibilityCandidatesKeepsOnlyExactMultiples(t *testing.T) {
	counts := map[string]int{"a": 761, "b": 1522, "c": 700, "d": 761 * 5, "e": 0}
	out, err := DivisibilityCandidates(counts, 761)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]int{"a": 1, "b": 2, "d": 5}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("DivisibilityCandidates = %v, want %v", out, want)
	}
}

func TestDivisibilityCandidatesRejectsNonpositiveWordlist(t *testing.T) {
	if _, err := DivisibilityCandidates(map[string]int{"a": 761}, 0); err == nil {
		t.Errorf("wordlistLen=0: expected error, got nil")
	}
	if _, err := DivisibilityCandidates(map[string]int{"a": 761}, -761); err == nil {
		t.Errorf("wordlistLen=-761: expected error, got nil")
	}
}

func TestDivisibilityCandidatesEmptyInput(t *testing.T) {
	out, err := DivisibilityCandidates(map[string]int{}, 761)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("DivisibilityCandidates(empty) = %v, want empty", out)
	}
}

func TestCredentialSetsMatchTrueWhenIdentical(t *testing.T) {
	pairs := wordlist(2, "")
	pairsCopy := wordlist(2, "")
	if !CredentialSetsMatch(map[string]map[CredentialPair]struct{}{
		"a": pairs, "b": pairs, "c": pairsCopy,
	}) {
		t.Errorf("CredentialSetsMatch = false, want true for identical sets")
	}
}

func TestCredentialSetsMatchFalseOnAnyMismatch(t *testing.T) {
	pairs := wordlist(1, "")
	other := wordlist(1, "_x")
	if CredentialSetsMatch(map[string]map[CredentialPair]struct{}{
		"a": pairs, "b": pairs, "c": other,
	}) {
		t.Errorf("CredentialSetsMatch = true, want false on mismatch")
	}
}

func TestCredentialSetsMatchVacuouslyTrueWhenEmpty(t *testing.T) {
	if !CredentialSetsMatch(map[string]map[CredentialPair]struct{}{}) {
		t.Errorf("CredentialSetsMatch(empty) = false, want true")
	}
}

func TestDetectCampaignReproducesATieredLadder(t *testing.T) {
	// Mirrors the shape of the preprint's Table II at a small scale: two
	// tier-1 addresses, one tier-2, sharing one 5-entry wordlist.
	shared := wordlist(5, "")
	sessionCounts := map[string]int{"1.1.1.1": 5, "2.2.2.2": 5, "3.3.3.3": 10, "noise": 7}
	pairSets := map[string]map[CredentialPair]struct{}{
		"1.1.1.1": shared, "2.2.2.2": shared, "3.3.3.3": shared,
	}

	result, err := DetectCampaign(sessionCounts, pairSets, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ips := result.IPs()
	sort.Strings(ips)
	wantIPs := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	if !reflect.DeepEqual(ips, wantIPs) {
		t.Errorf("IPs() = %v, want %v", ips, wantIPs)
	}
	if got := result.TotalSessions(); got != 20 {
		t.Errorf("TotalSessions() = %d, want 20", got)
	}
	wantTiers := map[int]TierStats{1: {NIPs: 2, NSessions: 10}, 2: {NIPs: 1, NSessions: 10}}
	if got := result.TierSummary(); !reflect.DeepEqual(got, wantTiers) {
		t.Errorf("TierSummary() = %v, want %v", got, wantTiers)
	}
	if len(result.Excluded) != 0 {
		t.Errorf("Excluded = %v, want empty", result.Excluded)
	}
}

func TestDetectCampaignExcludesACoincidentalDivisor(t *testing.T) {
	// An address hits a multiple of the wordlist length by chance but runs
	// a completely different credential list -- the negative-control
	// scenario from Section VI-B: the test must have specificity, not just
	// sensitivity.
	shared := wordlist(5, "")
	unrelated := wordlist(5, "_x")
	sessionCounts := map[string]int{"1.1.1.1": 5, "2.2.2.2": 5, "coincidence": 5}
	pairSets := map[string]map[CredentialPair]struct{}{
		"1.1.1.1": shared, "2.2.2.2": shared, "coincidence": unrelated,
	}

	result, err := DetectCampaign(sessionCounts, pairSets, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ips := result.IPs()
	sort.Strings(ips)
	wantIPs := []string{"1.1.1.1", "2.2.2.2"}
	if !reflect.DeepEqual(ips, wantIPs) {
		t.Errorf("IPs() = %v, want %v", ips, wantIPs)
	}
	if !reflect.DeepEqual(result.Excluded, []string{"coincidence"}) {
		t.Errorf("Excluded = %v, want [coincidence]", result.Excluded)
	}
}

func TestDetectCampaignNoCandidatesIsEmptyResult(t *testing.T) {
	result, err := DetectCampaign(map[string]int{"a": 700}, map[string]map[CredentialPair]struct{}{}, 761)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Members) != 0 || len(result.Excluded) != 0 {
		t.Errorf("DetectCampaign(no candidates) = %+v, want empty result", result)
	}
}

func TestDetectCampaignCandidateMissingCredentialDataIsExcluded(t *testing.T) {
	// A divisibility candidate with no auth_attempts rows at all (e.g.
	// partial ingest) must not be silently counted as a confirmed member.
	shared := wordlist(5, "")
	sessionCounts := map[string]int{"1.1.1.1": 5, "2.2.2.2": 5, "unknown": 5}
	pairSets := map[string]map[CredentialPair]struct{}{
		"1.1.1.1": shared, "2.2.2.2": shared,
	}

	result, err := DetectCampaign(sessionCounts, pairSets, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ips := result.IPs()
	sort.Strings(ips)
	wantIPs := []string{"1.1.1.1", "2.2.2.2"}
	if !reflect.DeepEqual(ips, wantIPs) {
		t.Errorf("IPs() = %v, want %v", ips, wantIPs)
	}
	if !reflect.DeepEqual(result.Excluded, []string{"unknown"}) {
		t.Errorf("Excluded = %v, want [unknown]", result.Excluded)
	}
}
