# nagios-ssllabs-rating

Python script to establish a web site's SSL Labs score, for use as a
Nagios/Icinga plugin.

# Installation and requirements

You will need python 3.5 or newer, and the yaml, packaging and requests modules.
For exmaple through the standard package manager:

```sh
   apt-get install python3 python3-yaml python3-requests
```

# Features

* Uses the [SSL Labs v3
  API](https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md)
* Configurable warning/critical thresholds (default B and C)
* Caches results

# Usage

```
usage: nagios-ssllabs-rating.py [-h] --host HOST [--proxy PROXY] [--warning WARNING] [--critical CRITICAL]
                                [--tempdir TEMPDIR]

Check the rating of an HTTPS web site with the SSLLabs API. See https://github.com/ssllabs/ssllabs-
scan/blob/master/ssllabs-api-docs-v3.md

options:
  -h, --help           show this help message and exit
  --host HOST          The hostname/FQDN to check
  --proxy PROXY        The proxy to use when connecting to the SSLLabs website
  --warning WARNING    Rating that triggers a WARNING (default: B)
  --critical CRITICAL  Rating that triggers a CRITICAL (default: C)
  --tempdir TEMPDIR    Directory to store cache files (default on this system:
                       /tmp)
```

The plugin tries to follow the [Nagios plugin guidelines](https://nagios-plugins.org/doc/guidelines.html#PLUGOUTPUT).
As such the first line of output is the status and the result.
The rest of the output is extra information, meant for nagios as
[`$LONGSERVICEOUTPUT$`](https://assets.nagios.com/downloads/nagioscore/docs/nagioscore/3/en/macrolist.html#longserviceoutput).

# Examples

Default usage:

```shell
~$ ./nagios-ssllabs-rating.py --host wiki.geant.org
OK: SSLLabs rating is A
See https://www.ssllabs.com/ssltest/analyze.html?d=wiki.geant.org

API result:

criteriaVersion: 2009q
endpoints:
- delegation: 1
  duration: 80026
  grade: A
  gradeTrustIgnored: A
  hasWarnings: false
  ipAddress: 2001:798:3:0:0:0:0:132
  isExceptional: false
  progress: 100
  serverName: prod-haproxy.geant.org
  statusMessage: Ready
- delegation: 1
  duration: 80528
  grade: A
  gradeTrustIgnored: A
  hasWarnings: false
  ipAddress: 83.97.93.30
  isExceptional: false
  progress: 100
  serverName: prod-haproxy.geant.org
  statusMessage: Ready
engineVersion: 2.1.5
host: wiki.geant.org
isPublic: false
port: 443
protocol: http
startTime: 1594723358496
status: READY
testTime: 1594723519403
```


To get notified earlier, you can use lower thresholds ratings. For instance:

```shell
~$ ./nagios-ssllabs-rating.py --host wiki.geant.org --warning A --critical B
WARNING: SSLLabs rating is A
See https://www.ssllabs.com/ssltest/analyze.html?d=wiki.geant.org

API result:

criteriaVersion: 2009q
endpoints:
- delegation: 1
  duration: 80026
  grade: A
  gradeTrustIgnored: A
  hasWarnings: false
  ipAddress: 2001:798:3:0:0:0:0:132
  isExceptional: false
  progress: 100
  serverName: prod-haproxy.geant.org
  statusMessage: Ready
- delegation: 1
  duration: 80528
  grade: A
  gradeTrustIgnored: A
  hasWarnings: false
  ipAddress: 83.97.93.30
  isExceptional: false
  progress: 100
  serverName: prod-haproxy.geant.org
  statusMessage: Ready
engineVersion: 2.1.5
host: wiki.geant.org
isPublic: false
port: 443
protocol: http
startTime: 1594723358496
status: READY
testTime: 1594723519403
```

You can also supply an HTTP proxy explicitly:

```shell
~$ ./nagios-ssllabs-rating.py --host wiki.geant.org --proxy
http://localhost:8000
OK: SSLLabs rating is A+
See https://www.ssllabs.com/ssltest/analyze.html?d=about.geant.org

API result:

criteriaVersion: 2009q
endpoints:
- delegation: 1
  duration: 130042
  grade: A+
  gradeTrustIgnored: A+
  hasWarnings: false
  ipAddress: 2001:798:3:0:0:0:0:132
  isExceptional: true
  progress: 100
  serverName: security.geant.org
  statusMessage: Ready
- delegation: 1
  duration: 130157
  grade: A+
  gradeTrustIgnored: A+
  hasWarnings: false
  ipAddress: 83.97.93.30
  isExceptional: true
  progress: 100
  serverName: tnc22.geant.org
  statusMessage: Ready
engineVersion: 2.2.0
host: about.geant.org
isPublic: false
port: 443
protocol: http
startTime: 1699541305491
status: READY
testTime: 1699541566057
```

# Tips/gotchas

* For FQDNs that have multiple endpoints (dual stack hosts etc), the plugin
reports the _worst_ score of the endpoints that _have_ a score. Endpoints
_without_ a score (like unreachable endpoints) are ignored when there are also
endpoints _with_ a score. The rationale is that this prevents common connectivity
problems from polluting the results of this plugin (which is about the score).
When there are _no_ endpoints at all, this _is_ reported however (as CRITICAL):

| Endpoints                                                                                            | Reported rating   | Reported result                                                |
|------------------------------------------------------------------------------------------------------|----------|----------------------------------------------------------------|
| - grade: A<br>- grade: A                                                                             | OK       | `SSL Labs rating is A`                                         |
| - grade: A<br>- grade: B                                                                             | WARNING  | `SSL Labs rating is B (but inconsistent across 2 endpoints)`   |
| - grade: A<br>- statusMessage: Unable to connect to the server                                       | OK       | `SSL Labs rating is A`                                         |
| - statusMessage: Unable to connect to the server<br>- statusMessage: Unable to connect to the server | CRITICAL | `SSL Labs rating failed with: Unable to connect to the server` |



* Starting up many probes at __exactly__ the same time will result in API
throttling. Don't do that.
* For use as a Nagios plugin, you can set the `tempdir` to something like `/var/cache/nagios3`,
  `/var/lib/nagios4/check_ssllabs/`, etc.
* TODO: migrate to v4 API
