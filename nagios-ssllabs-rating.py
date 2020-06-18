#!/usr/bin/env python3
import argparse
import sys
import os
import requests
import polling
import tempfile
import hashlib
import json
from packaging import version


from pprint import pprint
import logging
logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(message)s',
        filename='/tmp/ssllabs.log'
        )

def nagios_exit(message, code):
    print(message)
    sys.exit(code)

def report(host, grade, cached=False, ca=0, ma=0):
    cached_msg = " (locally cached result, could be stale)" if cached else ""
    msg = ("SSL Labs rating is " + grade + cached_msg +
        "\nSee https://www.ssllabs.com/ssltest/analyze.html?d=" + host + 
        "\nCurrently using " + str(ca) + " concurrent assessments (max " + str(ma) + ")")
    if version.parse(args.critical) <= version.parse(grade):
        crit_msg.append(msg)
    elif version.parse(args.warning) <= version.parse(grade):
        warn_msg.append(msg)
    else:
        ok_msg.append(msg)
    


try:

    tempdir = tempfile.gettempdir()

    parser = argparse.ArgumentParser(
            description='Check the rating of an HTTPS web site with the SSLLabs API. ' + 
                'See https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md'
            )
    parser.add_argument('--host',
            help='The hostname/FQDN to check',
            required=True
            )
    parser.add_argument('--warning',
            help='Rating that triggers a WARNING (default: B)',
            default="B"
            )
    parser.add_argument('--critical',
            help='Rating that triggers a CRITICAL (default: C)',
            default="C"
            )
    parser.add_argument('--tempdir',
            help='Directory to store cache files (default on this system: ' + tempdir + ')',
            default=tempdir
            )
    parser.add_argument('--verbose', '-v',
            help='Show verbose output',
            action='count',
            default=0
            )

   
    args = parser.parse_args()
 

    # start with clean slate
    ok_msg = []
    warn_msg = []
    crit_msg = []


    # Caching location
    cache_file = args.tempdir + "/ssllabs_check_" + hashlib.sha256(args.host.encode('utf-8')).hexdigest() + ".json"

    api = "https://api.ssllabs.com/api/v3/"
    # Fetch API information for this IP address
    api_status = requests.get(api + "info")
    logging.debug(api_status)
    current_assessments = api_status.json()["currentAssessments"]
    max_assessments = api_status.json()["maxAssessments"]

    if current_assessments >= max_assessments:
    # if args.verbose > 2:
        if args.verbose > 0:
            print("We have reached the maximum number of outstanding assessments of the SSL Labs API (" +
                    str(max_assessments) + "). Trying cached results from " + cache_file)
        if os.path.exists(cache_file):
            with open(cache_file) as cached_results:
                results = json.load(cached_results)
                # Report status
                # FIXME we only look at the first endpoint (the IPv4 one).
                # We should take the grades of all endpoints into account (how?)
                report(args.host, results["endpoints"][0]["grade"], True, current_assessments, max_assessments)
        else:
            crit_msg.append("Maximum number of concurrent assessments reached, and no cached results were found for " +
                    args.host)

    else:
        # We have enough assessments left
        if args.verbose > 0:
            print("There are " + str(current_assessments) + " active assessments")
        params = {
                "host": args.host,
                "fromCache": "on",
                # "all": "on",
                }
        polling.poll(
                lambda: requests.get(api + "analyze?", params=params).json()["status"] in ["READY", "ERROR"],
                step=5,
                poll_forever=True,
                )

        analyze_req = requests.get(api + "analyze?", params=params)
        if analyze_req.status_code == 200:
            results = analyze_req.json()
            if args.verbose > 0:
                pprint(results)
                # Store results
                print("Storing results as " + cache_file)
            if "endpoints" in results:
                with open(cache_file, "w") as fp:
                    json.dump(results, fp)

                if all('Ready' in e["statusMessage"] for e in results["endpoints"]):
                    # All endpoints are 'Ready' => report status
                    report(args.host, results["endpoints"][0]["grade"], False, current_assessments, max_assessments)
                else:
                    # Something strange happened (DNS resolution errors, unable to connect, etc) = Failure
                    status = ', '.join(list(set([sub["statusMessage"] for sub in results["endpoints"] if sub["statusMessage"] != "Ready"])))
                    crit_msg.append(status + "\n" + str(results["endpoints"]))
            else:
                # No results - some error
                crit_msg.append(results['statusMessage'])
        else:
            warn_msg.append("Too many concurrent assessments, or some other error")
            logging.debug(analyze_req.headers)


except Exception as e:
    if args.verbose > 0:
        pprint(e)
    nagios_exit("UNKNOWN: {0}.".format(e), 3)

# Exit with accumulated message(s)
if crit_msg:
    nagios_exit("CRITICAL: " + ' '.join(crit_msg + warn_msg), 2)
elif warn_msg:
    nagios_exit("WARNING: " + ' '.join(warn_msg), 1)
else:
    nagios_exit("OK: " + '\n'.join(ok_msg), 0)
