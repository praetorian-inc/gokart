package analyzers

import (
	"reflect"
	"testing"

	"github.com/praetorian-inc/gokart/test/testutil"
)

func TestResultTypes(t *testing.T) {
	for _, a := range Analyzers {
		t.Run(a.Name, func(t *testing.T) {
			in := testutil.MinimalPass(a)
			x, _ := a.Run(in)
			if got := reflect.TypeOf(x); got != a.ResultType {
				t.Errorf(
					"x, _ := %v.Run(%v); reflect.TypeOf(x) = %v, want %v",
					a.Name,
					in,
					got,
					a.ResultType,
				)
			}
		})
	}
}
