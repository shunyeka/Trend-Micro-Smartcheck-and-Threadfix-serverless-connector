import os
import sys
import json
import logging
import requests
from list_vulnerabilities import *

# Read all the environment variables
THREADFIX_URL = os.environ['THREADFIX_URL']
THREADFIX_VERSION = os.environ['THREADFIX_VERSION']
THREADFIX_ID = os.environ['THREADFIX_ID']
THREADFIX_API_KEY = "APIKEY " + os.environ['THREADFIX_API_KEY']
DSSC_URL = os.environ['DSSC_URL']
DSSC_SMARTCHECK_USER = os.environ['DSSC_SMARTCHECK_USER']
DSSC_SMARTCHECK_PASSWORD = os.environ['DSSC_SMARTCHECK_PASSWORD']
DSSC_MIN_SEVERITY = os.environ['DSSC_MIN_SEVERITY']
DSSC_SHOW_FIXED = os.environ['DSSC_SHOW_FIXED']
DSSC_SHOW_OVERRIDDEN = os.environ['DSSC_SHOW_OVERRIDDEN']
DSSC_INSECURE_SKIP_TLS_VERIFY = os.environ['DSSC_INSECURE_SKIP_TLS_VERIFY']

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    print(event["body"])
    if 'body' in event:
        jsonBody = json.loads(event['body'])
    else:
        jsonBody = event
    scan = jsonBody['scan']

    message = jsonBody['scan']['findings']['vulnerabilities']
    logger.info("Message: " + str(message))
    dssc_results = get_analysis(DSSC_URL, DSSC_SMARTCHECK_USER, DSSC_SMARTCHECK_PASSWORD, scan["name"],
                                DSSC_MIN_SEVERITY, DSSC_SHOW_FIXED, DSSC_SHOW_OVERRIDDEN, DSSC_INSECURE_SKIP_TLS_VERIFY)
    print(f"{dssc_results['vulnerable_package']['items']}")

    findings = []
    for result in dssc_results['vulnerable_package']['items']:
        finding = {
            "id": result['venerability'],
            "nativeId": result['venerability'] + "-" + THREADFIX_ID,
            "severity": result['severity'],
            "nativeSeverity": result['severity'],
            "summary": result['name'],
            "cvssScore": result['venerability'],
            "description": result['description'],
            "scannerDetail": result['description'],
            "scannerRecommendation": result['link'],
            "statuses": {"False Positive": False, "Exploitable": True},
            "dependencyDetails": {
                "library": result['name'],
                "description": result['description'],
                "reference": result['venerability'],
                "referenceLink": result['link'],
                "issueType": 'VULNERABILITY'
            },
            "metadata": {
                "vector": result['vector']
            },
            "mappings": []
        }
        findings.append(finding)
    print(findings)
    payload = {
        "id": scan["id"],
        "created": scan["details"]["started"],
        "updated": scan["details"]["updated"],
        "exported": scan["details"]["completed"],
        "collectionType": "DEPENDENCY",
        "source": "MyCustomScanner",
        "executiveSummary": scan["status"],
        "metadata": {
            "version": "1.2",
            "reviewed by third party": "true",
            "os": scan["details"]["os"],
            "architecture": scan["details"]["architecture"]
        },
        "findings": findings
    }

    # Write data in to .threadfix file
    f = open("/tmp/" + scan["id"] + ".threadfix", "w+")
    f.write(json.dumps(payload))
    f.close()

    # Fetch all the team & application ID and Name
    headers = {'Accept': 'application/json',
               'Authorization': THREADFIX_API_KEY}
    url = THREADFIX_URL + THREADFIX_VERSION + "/applications/" + THREADFIX_ID + "/upload"
    print(url)
    files = {'file': open("/tmp/" + scan["id"] + ".threadfix", 'rb')}
    if files is None:
        return {
            'statusCode': 404,
            'message': '.threadfix fil not found'
        }
    print(files)
    response = requests.post(url, headers=headers, files=files)
    print(response.status_code)
    return {
        'statusCode': response.status_code,
        'body': response.text
    }