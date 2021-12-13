package run

import (
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages"
)

var (
	pkgFoo = &packages.Package{
		ID: "foo",
	}
	pkgBar = &packages.Package{
		ID: "bar",
	}
	pkgBaz = &packages.Package{
		ID: "baz",
	}
)

func TestRemoveBadPackages(t *testing.T) {
	testCases := []struct {
		name        string
		badPackages map[*packages.Package]bool
		want        []*packages.Package
	}{
		{
			name:        "no bad packages",
			badPackages: nil,
			want:        []*packages.Package{pkgFoo, pkgBar, pkgBaz},
		},
		{
			name: "one bad package",
			badPackages: map[*packages.Package]bool{
				pkgFoo: true,
			},
			want: []*packages.Package{pkgBar, pkgBaz},
		},
		{
			name: "all packages are bad",
			badPackages: map[*packages.Package]bool{
				pkgFoo: true,
				pkgBar: true,
				pkgBaz: true,
			},
			want: []*packages.Package{},
		},
	}

	sortSlices := cmp.Transformer("Sort", func(in []*packages.Package) []*packages.Package {
		out := append([]*packages.Package(nil), in...)
		sort.SliceStable(out, func(i, j int) bool {
			return out[i].ID < out[j].ID
		})
		return out
	})
	cmpPkgs := cmp.Comparer(func(x, y *packages.Package) bool {
		return x.ID == y.ID
	})

	allPackages := []*packages.Package{pkgFoo, pkgBar, pkgBaz}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := RemoveBadPackages(allPackages, tc.badPackages)
			if diff := cmp.Diff(tc.want, got, cmpPkgs, sortSlices); diff != "" {
				t.Errorf("RemoveBadPackages(%v, %v) returned an unexpected diff (-want +got):\n%s", allPackages, tc.badPackages, diff)
			}
		})
	}
}
