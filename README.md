# SpringSAhell Detector

> A client and reporting server to identify systems vulnerable to springshell at
> scale. This work is based on [Stripe's Remediation Tools](https://github.com/stripe/log4j-remediation-tools),
> but with more in-depth fingerprints and a server for collecting the results
> for a more deployment-friendly rollout.

> The tool is divided up into three components, the detector, responsible for
> examining a target and determining if there is a currently-running java
> process that has loaded a vulnerable version of spring-jars, the server, responsible
> for collecting the results, and a log reader, which can quickly parse the
> server messages and output a list of reported vulnerable hosts.

## Building

The simplest way to build cross-platform artifacts for Linux, macOS, and Windows is `goreleaser`.

Follow the goreleaser [install instructions](https://goreleaser.com/install/) or use the following command on macOS:
```sh
brew install goreleaser
```

To build with goreleaser, use the following command:
```sh
goreleaser release --snapshot --rm-dist
```

This will create a `dist/` directory with artifacts for each platform.

### Server Config

If you know the hostname or IP address of your server, you can "bake" this into
the binaries at build time. This will allow end-users to run the detector
without passing any command line arguments. Use the following command to
pre-configure the server address:

```sh
REPORT_SERVER=https://example.org:8443 goreleaser release --snapshot --rm-dist
```

## Running

### Server

The server contains the following configuration options:

  - `-addr` - which address to listen on (default ":8443")
  - `-bin-dir` - the directory to serve the detector binaries from (default "./dist")
  - `-log-dir` - the directory where the server will write its logs to (default ".")
  - `-cert` - path to a TLS certificate file for use in web server (optional)
  - `-key` - path to a TLS key file for use in web server (optional)
  - `-slack-webhook` - a webhook URL for use in notification of vulnerable system
  - `-generic-webhook` - a generic webhook URL (e.g. AWS Lambda endpoint)
  - `-generic-webhook-auth` - a generic webhook auth header used to authenticate the report server
  - `-v` - print the version of the server

When the server starts, it will serve three endpoints,

  `/healthz` - returns 200 if the server is functional
  `/logs` - the endpoint the detector will talk to to record results
  `/bin` - a directory where the detector binaries will be served out of for
  retrieval by team members. This endpoint is merely for convenience and does not
  need to be used if detector binaries are distributed in other ways.

### Detector

The detector contains the following options:

  - `-server` - the url:port of the reporting server
  - `-verbose` - more verbose log messages
  - `-v` - prints the version of the tool

### Log Reader

The log reader contains the following options:

  - `-log` - the server's log file for parsing
  - `-v` - prints the version of the tool

## How it works

Like the Stripe tool that inspired this project, the detector locates Java
processes on the target host and then lists all open files and checks them for
the vulnerable spring jar. Once found, it will attempt to compare that jar with known
vulnerable versions of spring-mvc and spring-webflux. We have compiled a list of fingerprints for every
jar distributed by Spring. 
The inspiration for the improvements to this tool came from a client request,
and they also requested the addition of a central reporting server to collect
results so we decided to include that functionality as well.
