#!/usr/bin/env python3

# These come standard
import argparse
import sys
import os
import time
import tempfile
import hashlib
import json

# These can be installed through apt/yum
import requests
import yaml
from packaging import version


#from pprint import pprint


# TEMP logging... 
# import logging
# logging.basicConfig(
#         level=logging.DEBUG,
#         format='%(asctime)s %(message)s',
#         filename='/tmp/ssllabs.log'
#         )

def nagios_exit(message, code):
    print(message)
    sys.exit(code)

def report(results):
    info_line = "\nSee https://www.ssllabs.com/ssltest/analyze.html?d=" + results['host']
    debug_info = "\n\nAPI result:\n\n" + yaml.dump(results, default_flow_style=False)
    if 'endpoints' in results:

        # Create list of unique statuses across all reported endpoints
        statuses = list(set([ sub["statusMessage"] for sub in results["endpoints"]]))

        # At least one endpoint is 'Ready' => report the worst grade across all of them
        if 'Ready' in statuses:

            # List of unique grades
            grades = list(set([ sub['grade'] for sub in results['endpoints'] if 'grade' in sub]))
            grade = sorted(grades, key=lambda x: version.parse(x))[-1]

            # Endpoint inconsistency message
            if (len(statuses) > 1) or (len(grades) > 1):
                inconsistency_msg = " (but inconsistent across " + str(len(results['endpoints'])) + " endpoints)"
            else:
                inconsistency_msg = ""

            msg = "SSLLabs rating is " + grade + inconsistency_msg +  info_line + debug_info

            if version.parse(args.critical) <= version.parse(grade):
                crit_msg.append(msg)
            elif version.parse(args.warning) <= version.parse(grade):
                warn_msg.append(msg)
            else:
                ok_msg.append(msg)

        # None of the endpoints is 'Ready'. This usually happens when all of the
        # host's IP addresses are inaccessible (firewall/ACLs/etc).
        else:
            msg = "SSL Labs rating failed with: " + (', '.join(statuses)) + info_line + debug_info
            crit_msg.append(msg)
    else:
        # No endpoints - usually the result of issues that prevent the tests
        # from running at all (like DNS resolution failures)
        msg = results['statusMessage'] + info_line + debug_info
        crit_msg.append(msg)


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

   
    args = parser.parse_args()
 

    # start with clean slate
    ok_msg = []
    warn_msg = []
    crit_msg = []

    # Ensure tempdir exists
    from pathlib import Path
    Path(args.tempdir).mkdir(parents=True, exist_ok=True)

    # Caching location
    cache_file = args.tempdir + "/ssllabs_check_" + hashlib.sha256(args.host.encode('utf-8')).hexdigest() + ".json"

    api = "https://api.ssllabs.com/api/v3/"
    # Fetch API information for this IP address
    api_status = requests.get(api + "info")
    # logging.debug(api_status)
    current_assessments = api_status.json()["currentAssessments"]
    max_assessments = api_status.json()["maxAssessments"]

    if current_assessments >= max_assessments:
    #if args.verbose > 2:
#        if args.verbose > 0:
#            print("We have reached the maximum number of outstanding assessments of the SSL Labs API (" +
#                    str(max_assessments) + "). Trying cached results from " + cache_file)
        if os.path.exists(cache_file):
            with open(cache_file) as cached_results:
                results = json.load(cached_results)
                report(results)
        else:
            crit_msg.append("Maximum number of concurrent assessments reached, and no cached results were found for " +
                    args.host)

    else:
        # We have enough assessments left
#        if args.verbose > 0:
#            print("There are " + str(current_assessments) + " active assessments")
        params = {
                "host": args.host,
                "fromCache": "on",
                # "all": "on",
                }

        # Poll the API
        while True:
            response = requests.get(api + "analyze?", params=params)
            if response.status_code != 200:
                break
            if response.json()['status'] in ['READY', 'ERROR']:
                break
            time.sleep(5)


        if response.status_code == 200:
            results = response.json()
#            if args.verbose > 0:
#                pprint(results)
            # Store results
            with open(cache_file, "w") as fp:
                json.dump(results, fp)
            # Report results
            report(results)
        else:
            # https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md#error-response-status-codes
            # FIXME This should never happen, but we should be able to handle it
            debug_info = "\n\nHTTP response headers:\n\n" + yaml.dump(response.headers, default_flow_style=False)
            crit_msg.append("Received HTTP " + str(response.status_code) + " from SSL Labs API" +
                    "\nSee https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md#error-response-status-codes" +
                    debug_info)


except Exception as e:
#    if args.verbose > 0:
#        pprint(e)
    nagios_exit("UNKNOWN: {0}.".format(e), 3)

# Exit with accumulated message(s)
if crit_msg:
    nagios_exit("CRITICAL: " + ' '.join(crit_msg + warn_msg), 2)
elif warn_msg:
    nagios_exit("WARNING: " + ' '.join(warn_msg), 1)
else:
    nagios_exit("OK: " + '\n'.join(ok_msg), 0)
