package validity

import "sort"

// CardinalityResult summarizes one field's value distribution over a
// window. The zero value represents "no data."
type CardinalityResult struct {
	Total         int
	DistinctCount int
	ModalValue    string
	ModalShare    float64 // modal count / Total; 0 when Total == 0
}

// AssessCardinality computes distinct-value count and modal-value share
// from raw {value: count} counts (as produced by a `GROUP BY column`
// query). Ties for the modal value resolve to the lexicographically
// smallest value, for a result that's reproducible across runs rather than
// dependent on Go's randomized map iteration order.
func AssessCardinality(counts map[string]int) CardinalityResult {
	if len(counts) == 0 {
		return CardinalityResult{}
	}

	values := make([]string, 0, len(counts))
	for v := range counts {
		values = append(values, v)
	}
	sort.Strings(values)

	total := 0
	modalValue := values[0]
	modalCount := counts[modalValue]
	for _, v := range values {
		c := counts[v]
		total += c
		if c > modalCount {
			modalCount, modalValue = c, v
		}
	}

	return CardinalityResult{
		Total:         total,
		DistinctCount: len(counts),
		ModalValue:    modalValue,
		ModalShare:    float64(modalCount) / float64(total),
	}
}

// DetectCardinalityCollapse reports whether a field that had real variance
// in baseline has collapsed to (near-)one value in current. Flags a
// *change*, not a steady state: a field with no baseline data, or one that
// was already collapsed in baseline, is not flagged -- a standing
// single-value field should already have been caught when it first
// appeared, not re-flagged on every subsequent window forever.
func DetectCardinalityCollapse(baseline, current CardinalityResult, maxModalShare float64) bool {
	if baseline.Total == 0 || current.Total == 0 {
		return false
	}
	if baseline.ModalShare > maxModalShare {
		return false // already collapsed in the baseline window -- not new
	}
	return current.ModalShare > maxModalShare
}
