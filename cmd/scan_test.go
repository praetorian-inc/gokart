package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/praetorian-inc/gokart/util"
	"github.com/spf13/cobra"
)

func TestScanCommand(t *testing.T) {
	// Tests the Scan command.
	cur_dir, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Current dir is: %s", cur_dir)
	var tests = []struct {
		args              []string
		expected_lastline string
		moduledir         string
	}{
		{[]string{"scan"}, "GoKart found 0 potentially vulnerable functions", ""},
		{[]string{"scan", "-r", "github.com/praetorian-inc/gokart"}, "GoKart found 0 potentially vulnerable functions", cur_dir + "/gokart"},
		{[]string{"scan", "--help"}, "  -v, --verbose               outputs full trace of taint analysis", ""},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {

			if err != nil {
				t.Fatalf("Failed! %s", err)
			}

			// fetch last line of output from scan command
			lastline := ExecuteCommand(goKartCmd, tt.args)
			//if we tested with a remote module clean it up.
			if len(tt.moduledir) != 0 {
				err := util.CleanupModule(tt.moduledir)
				if err != nil {
					fmt.Print(err)
				}
			}
			if lastline != tt.expected_lastline {
				t.Fatalf("Failed! Expected: %s\nGot: %s\n", tt.expected_lastline, lastline)
			}
		})
	}
}

func ExecuteCommand(cmd *cobra.Command, args []string) string {

	// change stdout to something we can read from to capture command out
	// Not sure if this could potentially cause issues if buffer gets too full
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w

	cmd.SetArgs(args)
	Execute()

	// reset stdout to normal stdout and read output from cmd
	w.Close()
	stdoutres, _ := ioutil.ReadAll(r)
	os.Stdout = old

	//get the last line of output for comparison with our tests
	stdoutresslice := strings.Split(strings.ReplaceAll(string(stdoutres), "\r\n", "\n"), "\n")
	lastline := stdoutresslice[len(stdoutresslice)-2]
	return lastline

}
