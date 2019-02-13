#!/usr/bin/python3
import argparse
import os
import urllib
import requests
from concurrent.futures import ThreadPoolExecutor

# Disable warnings SSL warnings; ideal for sites with bad SSL setup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

HEADERS = ["X-XSS-Protection",
           "X-Frame-Options",
           "Content-Security-Policy",
           "X-Content-Type-Options",
           "Referrer-Policy",
           "Feature-Policy"]


def checkSchema(target: str, schema="https") -> str:
    """
    Attempts to check if the schema of a given URL is valid,
    prepends given schema if not; default HTTPS
    """
    parsed = urllib.parse.urlparse(target)
    return "{schema}://{target}".format(target=target, schema=schema)\
        if not bool(parsed.scheme) else target


def parseTargets(targets: str) -> set:
    """
    Parses a given target(s) - if a file is provided,
    attempts to parse assuming it's newline separated
    Also accepts a single target
    Returns results as a set
    """
    results = []
    if os.path.isfile(targets):
        with open(targets) as f:
            for line in f:
                results.append(checkSchema(line.strip()))
    else:
        results.append(checkSchema(targets))
    return set(results)


def cookieToDict(cookies: str) -> dict:
    """
    Converts a cookie string to a dict, expects the form:
    name1=value1; name2=value2; ...
    """
    finalCookies = {}
    if cookies is not None:
        cookieList = cookies.split(";")
        for cookieItem in cookieList:
            cookie = cookieItem.split("=")
            finalCookies[cookie[0].strip()] = cookie[1].strip()
    return finalCookies


def getHeaders(target: str, cookies: str) -> list:
    """
    Gets security headers for given URL, returns as a list in the form:
    [URL,X-XSS-Protection,"X-Frame-Options,Content-Security-Policy,
    X-Content-Type-Options,"Referrer-Policy,Feature-Policy]
    Headers are returned as bool
    """
    try:
        result = requests.get(target, verify=False,
                              timeout=3, cookies=cookieToDict(cookies))
    except Exception as e:
        print(e)
        return []

    return [target] + list(map(lambda x: True if x in result.headers
                               else False, HEADERS))


def main(targets: str, cookies: str, outfile: str):
    """
    Main function, takes a target name/file and parses them,
    passes to thread pool and ultimately writes to the outfile in CSV format
    """
    targets = parseTargets(targets)

    args = ((target, cookies) for target in targets)
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(lambda arg: getHeaders(*arg), args, timeout=10)

    with open(outfile, 'w+') as f:
        f.write("URL,{}\n".format(",".join(HEADERS)))
        for result in results:
            print(result)
            if len(result) > 0:
                f.write("{},{}\n".format(result[0], ",".join(
                    ["Yes" if x else "No" for x in result[1:]]
                )))

    print("[+] Results written to {}".format(outfile))


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Parse the security headers of a target")
    parser.add_argument(
        "-t", "--target",
        help="Single target or file of newline seperated targets",
        required=True)
    parser.add_argument("-c", "--cookies",
                        help="Cookies to use when forming a connection")
    parser.add_argument("-o", "--outfile", default="shredder.csv",
                        help="File to write 'result info' to;\
                         CSV format; defaults to shredder.csv")
    args = parser.parse_args()

    main(args.target, args.cookies, args.outfile)
