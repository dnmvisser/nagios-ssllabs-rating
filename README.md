# nagios-ssllabs-rating

Python script to establish a web site's SSL Labs score, for use as a
Nagios/Icinga plugin.

# Installation and requirements

You will need python 3.5 or newer, and the yaml, packaging and requests modules. Easiest
through the standard package manager:

```sh
   apt-get install python3 python3-yaml python3-requests python3-packaging
```

# Features

* Uses the [SSL Labs v3
  API](https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md)
* Configurable warning/critical thresholds (default B and C)
* Caches results

# Usage

```
usage: nagios-ssllabs-rating.py [-h] --host HOST [--warning WARNING]
                                [--critical CRITICAL] [--tempdir TEMPDIR]

Check the rating of an HTTPS web site with the SSLLabs API. See
https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md

optional arguments:
  -h, --help           show this help message and exit
  --host HOST          The hostname/FQDN to check
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

```
~$ ./nagios-ssllabs-rating.py --host wiki.geant.org
OK: SSLLabs rating is A
See https://www.ssllabs.com/ssltest/analyze.html?d=wiki.geant.org

API result:

criteriaVersion: 2009q
endpoints:
- delegation: 1
  duration: 79614
  grade: A
  gradeTrustIgnored: A
  hasWarnings: false
  ipAddress: 2001:798:3:0:0:0:0:132
  isExceptional: false
  progress: 100
  serverName: prod-haproxy.geant.org
  statusMessage: Ready
- delegation: 1
  duration: 84891
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
startTime: 1594136381900
status: READY
testTime: 1594136547059
```

To get notified earlier, you can use lower thresholds ratings. For instance:

```
~$ ./nagios-ssllabs-rating.py --host wiki.geant.org --warning A --critical B
WARNING: SSLLabs rating is A
See https://www.ssllabs.com/ssltest/analyze.html?d=wiki.geant.org

API result:

criteriaVersion: 2009q
endpoints:
- delegation: 1
  duration: 79614
  grade: A
  gradeTrustIgnored: A
  hasWarnings: false
  ipAddress: 2001:798:3:0:0:0:0:132
  isExceptional: false
  progress: 100
  serverName: prod-haproxy.geant.org
  statusMessage: Ready
- delegation: 1
  duration: 84891
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
startTime: 1594136381900
status: READY
testTime: 1594136547059
```


# Tips/gotchas

* Starting up many probes at __exactly__ the same time will result in API
throttling. Don't do that.
* For use as a Nagios plugin, you can set the `tempdir` to something like `/var/cache/nagios3`,
  `/var/lib/nagios4/check_ssllabs/`, etc.

