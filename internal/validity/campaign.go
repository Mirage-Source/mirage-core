// Package validity implements the MIRAGE data-validity toolkit: standing
// checks that generalize the preprint's audit findings ("A Labeled SSH
// Honeypot Dataset, and What Auditing It Revealed About Honeypot Data
// Validity") into reusable, continuously-run checks against a live corpus.
package validity

import (
	"fmt"
	"sort"
	"strings"
)

// WordlistLen is the credential wordlist length identified in the MIRAGE
// preprint, Section VI-A -- the campaign's structural signature is an exact
// integer multiple of this many sessions per source address.
const WordlistLen = 761

// CredentialPair is a (username, credential) pair as tried in one auth
// attempt.
type CredentialPair struct {
	Username   string
	Credential string
}

// CampaignMembership is one confirmed campaign member.
type CampaignMembership struct {
	IP           string
	Tier         int // How many times this address replayed the wordlist.
	SessionCount int
}

// CampaignResult is the output of DetectCampaign.
type CampaignResult struct {
	// Members are confirmed campaign addresses (passed both the
	// divisibility test and the credential-set-identity check).
	Members []CampaignMembership
	// Excluded addresses had a session count divisible by the wordlist
	// length but a credential-pair set that didn't match the campaign's --
	// a coincidental divisor, not a real member. Reported rather than
	// silently dropped so a caller can see the test has specificity
	// (mirrors the paper's negative control, Section VI-B).
	Excluded []string
}

// IPs returns the confirmed member addresses, in the order Members is
// stored (callers that need a stable order should sort the result).
func (r CampaignResult) IPs() []string {
	ips := make([]string, len(r.Members))
	for i, m := range r.Members {
		ips[i] = m.IP
	}
	return ips
}

// TotalSessions sums SessionCount across all confirmed members.
func (r CampaignResult) TotalSessions() int {
	total := 0
	for _, m := range r.Members {
		total += m.SessionCount
	}
	return total
}

// TierStats is {n_ips, n_sessions} for one tier.
type TierStats struct {
	NIPs      int
	NSessions int
}

// TierSummary groups confirmed members by tier, matching the preprint's
// Table II.
func (r CampaignResult) TierSummary() map[int]TierStats {
	out := map[int]TierStats{}
	for _, m := range r.Members {
		s := out[m.Tier]
		s.NIPs++
		s.NSessions += m.SessionCount
		out[m.Tier] = s
	}
	return out
}

// DivisibilityCandidates returns addresses whose session count is a
// positive exact multiple of wordlistLen, as {ip: tier} where
// tier = sessionCount / wordlistLen.
//
// This is the paper's primary test (Section VI-A): testing for
// divisibility rather than equality is what surfaces the tiered campaign
// structure that an equality test (e.g. "count == 761") would miss.
func DivisibilityCandidates(sessionCounts map[string]int, wordlistLen int) (map[string]int, error) {
	if wordlistLen <= 0 {
		return nil, fmt.Errorf("validity: wordlistLen must be positive, got %d", wordlistLen)
	}
	out := map[string]int{}
	for ip, n := range sessionCounts {
		if n > 0 && n%wordlistLen == 0 {
			out[ip] = n / wordlistLen
		}
	}
	return out, nil
}

// credentialSetKey canonicalizes a credential-pair set into a stable string
// key. A Go map isn't itself comparable or usable as a map key, so equality
// and "most common set" both go through this rather than direct map
// comparison.
func credentialSetKey(set map[CredentialPair]struct{}) string {
	pairs := make([]string, 0, len(set))
	for p := range set {
		pairs = append(pairs, p.Username+"\x00"+p.Credential)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "\x01")
}

// CredentialSetsMatch reports whether every address's credential-pair set
// is identical (vacuously true if pairSets is empty).
func CredentialSetsMatch(pairSets map[string]map[CredentialPair]struct{}) bool {
	first, seen := "", false
	for _, set := range pairSets {
		key := credentialSetKey(set)
		if !seen {
			first, seen = key, true
			continue
		}
		if key != first {
			return false
		}
	}
	return true
}

// DetectCampaign runs the full two-stage structural-signature test (paper
// Section VI-A/VI-B).
//
// Stage 1 (DivisibilityCandidates) finds addresses whose session count is
// an exact multiple of the wordlist length -- necessary but not sufficient,
// since an unrelated address could hit a multiple by coincidence. Stage 2
// confirms each candidate's credential-pair set is identical to the
// campaign's (the *mode* of all candidates' sets, so one corrupted or
// coincidental candidate can't skew the reference); a candidate whose set
// doesn't match is reported as excluded rather than silently dropped, so
// the test's specificity is visible.
//
// Tie-breaking for the reference set iterates candidate IPs in sorted
// order. This deliberately diverges from the Python original (which
// effectively breaks ties by dict-insertion order via Counter.most_common):
// Go map iteration order is randomized, so mirroring "insertion order"
// isn't available, and sorted-IP order gives a deterministic result
// independent of caller-supplied map order instead.
func DetectCampaign(sessionCounts map[string]int, credentialPairSets map[string]map[CredentialPair]struct{}, wordlistLen int) (CampaignResult, error) {
	candidates, err := DivisibilityCandidates(sessionCounts, wordlistLen)
	if err != nil {
		return CampaignResult{}, err
	}
	if len(candidates) == 0 {
		return CampaignResult{}, nil
	}

	candidateIPs := make([]string, 0, len(candidates))
	for ip := range candidates {
		candidateIPs = append(candidateIPs, ip)
	}
	sort.Strings(candidateIPs)

	keys := make(map[string]string, len(candidateIPs)) // ip -> canonical set key
	for _, ip := range candidateIPs {
		if set, ok := credentialPairSets[ip]; ok {
			keys[ip] = credentialSetKey(set)
		}
	}
	if len(keys) == 0 {
		return CampaignResult{Excluded: append([]string(nil), candidateIPs...)}, nil
	}

	counts := map[string]int{}
	for _, ip := range candidateIPs {
		if key, ok := keys[ip]; ok {
			counts[key]++
		}
	}
	referenceKey, best := "", -1
	for _, ip := range candidateIPs {
		key, ok := keys[ip]
		if !ok {
			continue
		}
		if c := counts[key]; c > best {
			best, referenceKey = c, key
		}
	}

	var members []CampaignMembership
	var excluded []string
	for _, ip := range candidateIPs {
		if key, ok := keys[ip]; ok && key == referenceKey {
			members = append(members, CampaignMembership{
				IP: ip, Tier: candidates[ip], SessionCount: sessionCounts[ip],
			})
		} else {
			excluded = append(excluded, ip)
		}
	}
	return CampaignResult{Members: members, Excluded: excluded}, nil
}
