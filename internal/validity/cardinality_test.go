package validity

import "testing"

func TestAssessCardinalityEmpty(t *testing.T) {
	got := AssessCardinality(map[string]int{})
	want := CardinalityResult{}
	if got != want {
		t.Errorf("AssessCardinality(empty) = %+v, want %+v", got, want)
	}
}

func TestAssessCardinalitySingleValue(t *testing.T) {
	got := AssessCardinality(map[string]int{"auth_failed": 4200})
	if got.Total != 4200 || got.DistinctCount != 1 {
		t.Errorf("Total/DistinctCount = %d/%d, want 4200/1", got.Total, got.DistinctCount)
	}
	if got.ModalValue != "auth_failed" || got.ModalShare != 1.0 {
		t.Errorf("ModalValue/ModalShare = %q/%v, want auth_failed/1.0", got.ModalValue, got.ModalShare)
	}
}

func TestAssessCardinalityMultipleValues(t *testing.T) {
	got := AssessCardinality(map[string]int{
		"auth_failed":      700,
		"clean_disconnect": 250,
		"timeout":          50,
	})
	if got.Total != 1000 || got.DistinctCount != 3 {
		t.Errorf("Total/DistinctCount = %d/%d, want 1000/3", got.Total, got.DistinctCount)
	}
	if got.ModalValue != "auth_failed" {
		t.Errorf("ModalValue = %q, want auth_failed", got.ModalValue)
	}
	if got.ModalShare != 0.7 {
		t.Errorf("ModalShare = %v, want 0.7", got.ModalShare)
	}
}

func TestAssessCardinalityTieBreaksOnLowestValueName(t *testing.T) {
	// Deterministic tie-break needed since map iteration order is
	// randomized -- ties resolve to the lexicographically smallest value so
	// results are reproducible across runs, not just "some tied value."
	got := AssessCardinality(map[string]int{"zzz": 5, "aaa": 5})
	if got.ModalValue != "aaa" {
		t.Errorf("ModalValue = %q, want aaa (lexicographically smallest on tie)", got.ModalValue)
	}
}

func TestDetectCardinalityCollapseFlagsANewCollapse(t *testing.T) {
	baseline := AssessCardinality(map[string]int{"auth_failed": 700, "clean_disconnect": 250, "timeout": 50})
	current := AssessCardinality(map[string]int{"auth_failed": 1000})
	if !DetectCardinalityCollapse(baseline, current, 0.99) {
		t.Errorf("DetectCardinalityCollapse = false, want true (varied baseline, collapsed current)")
	}
}

func TestDetectCardinalityCollapseNoFlagWhenStillVaried(t *testing.T) {
	baseline := AssessCardinality(map[string]int{"auth_failed": 700, "clean_disconnect": 300})
	current := AssessCardinality(map[string]int{"auth_failed": 680, "clean_disconnect": 320})
	if DetectCardinalityCollapse(baseline, current, 0.99) {
		t.Errorf("DetectCardinalityCollapse = true, want false (both windows still varied)")
	}
}

func TestDetectCardinalityCollapseNoFlagWhenAlreadyCollapsedInBaseline(t *testing.T) {
	// A field that has ALWAYS been single-valued isn't new information --
	// this check is about a change, not a steady state (a standing
	// single-value field is check 2's job to have already flagged on
	// arrival, not to re-flag every window forever).
	baseline := AssessCardinality(map[string]int{"auth_failed": 1000})
	current := AssessCardinality(map[string]int{"auth_failed": 1000})
	if DetectCardinalityCollapse(baseline, current, 0.99) {
		t.Errorf("DetectCardinalityCollapse = true, want false (baseline was already collapsed)")
	}
}

func TestDetectCardinalityCollapseNoFlagOnEmptyBaseline(t *testing.T) {
	baseline := CardinalityResult{}
	current := AssessCardinality(map[string]int{"auth_failed": 1000})
	if DetectCardinalityCollapse(baseline, current, 0.99) {
		t.Errorf("DetectCardinalityCollapse = true, want false (no baseline data to compare against)")
	}
}
