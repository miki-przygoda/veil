package subject

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestScriptedBrainWalksVectorsThenStops(t *testing.T) {
	b := NewScriptedBrain()
	var hist []Turn
	var got []string
	for i := 0; i < len(scriptedPlan)+2; i++ {
		act, err := b.Decide(context.Background(), "g", hist)
		if err != nil {
			t.Fatalf("Decide: %v", err)
		}
		if act.Stop {
			break
		}
		got = append(got, act.Command)
		hist = append(hist, Turn{Command: act.Command})
	}
	if !reflect.DeepEqual(got, scriptedPlan) {
		t.Errorf("plan = %v, want %v", got, scriptedPlan)
	}
	// After the full plan, it must Stop.
	if act, _ := b.Decide(context.Background(), "g", make([]Turn, len(scriptedPlan))); !act.Stop {
		t.Error("scripted brain must Stop after the plan is exhausted")
	}
	// The plan probes outward by name and by IP + proves persistence.
	joined := strings.Join(got, " ")
	for _, want := range []string{"nslookup", "169.254.169.254", "pwd"} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan missing %q (vector coverage)", want)
		}
	}
}
