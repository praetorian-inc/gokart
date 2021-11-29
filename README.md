<p align="center">
    <img src="docs/img/logo.png" width="75%">
</p>

# GoKart - Go Security Static Analysis

[![CI](https://github.com/praetorian-inc/gokart/workflows/CI/badge.svg)](actions?query=branch%3Adevelopment)
[![Release](https://github.com/praetorian-inc/gokart/workflows/Release/badge.svg)](releases)

GoKart is a static analysis tool for Go that finds vulnerabilities using
the SSA (single static assignment) form of Go source code. It is capable of
tracing the source of variables and function arguments to determine whether
input sources are safe, which reduces the number of false positives compared
to other Go security scanners. For instance, a SQL query that is concatenated with a variable might
traditionally be flagged as SQL injection; however, GoKart can figure out if the variable
is actually a constant or constant equivalent, in which case there is no vulnerability.

GoKart also helps to power [**Chariot**](https://lp.praetorian.com/l/874901/2021-11-24/dtw1j?utm_source=github&utm_medium=organic_oss&utm_campaign=gokart),
Praetorian's security platform that helps you find, manage, and fix vulnerabilities in your source
code and cloud environments. Chariot makes it simple to run automated, continuous GoKart scans on
your source code. If you want to try GoKart, you can set up a free Chariot account in minutes by
clicking [here](https://chariot.praetorian.com/app/login?register&utm_source=github&utm_medium=organic_oss&utm_campaign=gokart).

## Why We Built GoKart

Static analysis is a powerful technique for finding vulnerabilities in source code. 
However, the approach has suffered from being noisy - that is, many static analysis
tools find quite a few "vulnerabilities" that are not actually real. This has led
to developer friction as users get tired of the tools "crying wolf" one time too
many.

The motivation for GoKart was to address this: could we create a scanner with 
significantly lower false positive rates than existing tools? Based on our experimentation
the answer is yes. By leveraging source-to-sink tracing and SSA, GoKart is capable
of tracking variable taint between variable assignments, significantly improving the 
accuracy of findings. Our focus is on usability: pragmatically, that means we 
have optimized our approaches to reduce false alarms.

For more information, please read [our blog post](https://www.praetorian.com/blog/introducing-gokart/utm_source=github&utm_medium=organic_oss&utm_campaign=gokart).

## Install

You can install GoKart locally by using any one of the options listed below.

### Install with `go install`

```shell
$ go install github.com/praetorian-inc/gokart@latest
```

### Install a release binary

1. Download the binary for your OS from the [releases page](https://github.com/praetorian-inc/gokart/releases).

2. (OPTIONAL) Download the `checksums.txt` file to verify the integrity of the archive

```shell
# Check the checksum of the downloaded archive
$ shasum -a 256 gokart_${VERSION}_${ARCH}.tar.gz
b05c4d7895be260aa16336f29249c50b84897dab90e1221c9e96af9233751f22  gokart_${VERSION}_${ARCH}.tar.gz

$ cat gokart_${VERSION}_${ARCH}_checksums.txt | grep gokart_${VERSION}_${ARCH}.tar.gz
b05c4d7895be260aa16336f29249c50b84897dab90e1221c9e96af9233751f22  gokart_${VERSION}_${ARCH}.tar.gz
```

3. Extract the downloaded archive

```shell
$ tar -xvf gokart_${VERSION}_${ARCH}.tar.gz
```

4. Move the `gokart` binary into your path:

```shell
$ mv ./gokart /usr/local/bin/
```

### Clone and build yourself

```shell
# clone the GoKart repo
$ git clone https://github.com/praetorian-inc/gokart.git

# navigate into the repo directory and build
$ cd gokart
$ go build

# Move the gokart binary into your path
$ mv ./gokart /usr/local/bin
```

### Docker Support
Build the docker image
```shell
docker build -t gokart .
```

Running the container with a local scan (the local scan directory needs to be mounted to the container image)
```shell
docker run -v /path/to/scan-dir:/scan-dir gokart scan /scan-dir
```

Running the container with a remote scan (when specifying a private key for auth, that will also need to be mounted to the container)
```shell
docker run gokart scan -r https://github.com/praetorian-inc/gokart

# specifying a private key for private repository ssh authentication
docker run -v /path/to/key-dir/:/key-dir gokart scan -r git@github.com:praetorian-inc/gokart.git -k /key-dir/ssh_key
```

## Usage

### Run GoKart on a Go module in the current directory

```shell
# running without a directory specified defaults to '.'
gokart scan <flags>
```

### Scan a Go module in a different directory

```shell
gokart scan <directory> <flags> 
```

### Get Help

```shell
gokart help
```

## Getting Started - Scanning an Example App

You can follow the steps below to run GoKart on [Go Test Bench](https://github.com/Contrast-Security-OSS/go-test-bench),
an intentionally vulnerable Go application from the Contrast Security team.

```shell
# Clone sample vulnerable application
git clone https://github.com/Contrast-Security-OSS/go-test-bench.git
gokart scan go-test-bench/
```

Output should show some identified vulnerabilities, each with a Vulnerable Function and Source of
User Input identified.

To test some additional GoKart features, you can scan with the CLI flags suggested below.

```shell
# Use verbose flag to show full traces of these vulnerabilities
gokart scan go-test-bench/ -v

# Use globalsTainted flag to ignore whitelisted Sources
# may increase false positive results
gokart scan go-test-bench/ -v -g

# Use debug flag to display internal analysis information
# which is useful for development and debugging
gokart scan go-test-bench/ -d

# Output results in sarif format
gokart scan go-test-bench/ -s

# Output results to file
gokart scan go-test-bench/ -o gokart-go-test-bench.txt

# Output scarif results to file
gokart scan go-test-bench/ -o gokart-go-test-bench.txt -s

# Scan remote public repository 
# Repository will be cloned locally, scanned and deleted afterwards
gokart scan -r https://github.com/ShiftLeftSecurity/shiftleft-go-demo -v

# Specify the remote branch to scan
gokart scan -r https://github.com/ShiftLeftSecurity/shiftleft-go-demo -b actions_fix

# Scan remote private repository via ssh
gokart scan -r git@github.com:Contrast-Security-OSS/go-test-bench.git 

# Scan remote private repository and optionally specify a key for ssh authentication 
gokart scan -r git@github.com:Contrast-Security-OSS/go-test-bench.git -k /home/gokart/.ssh/github_rsa_key

# Use remote scan and output flags together for seamless security reviews
gokart scan -r https://github.com/ShiftLeftSecurity/shiftleft-go-demo -o gokart-shiftleft-go-demo.txt -v 

# Use remote scan, output and sarif flags for frictionless integration into CI/CD
gokart scan -r https://github.com/ShiftLeftSecurity/shiftleft-go-demo -o gokart-shiftleft-go-demo.txt -s
```

To test out the extensibility of GoKart, you can modify the configuration file that GoKart uses to
introduce a new vulnerable sink into analysis. There is a Test Sink analyzer defined in the included
default config file at `util/analyzers.yml`. Modify `util/analyzers.yml` to remove the comments on
the Test Sink analyzer and then direct GoKart to use the modified config file with the `-i` flag.

```shell
# Scan using modified analyzers.yml file and output full traces
gokart scan go-test-bench/ -v -i <path-to-gokart>/util/analyzers.yml
```

Output should now contain additional vulnerabilities, including new "Test Sink reachable by user input"
vulnerabilities.

## Run GoKart Tests

You can run the included tests with the following command, invoked from the GoKart root directory.

```shell
go test -v ./...
```
