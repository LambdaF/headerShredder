# headerShredder
Parses common security headers from given URL(s), outputs to csv.

Parsed headers are:
`X-XSS-Protection, X-Frame-Options, Content-Security-Policy, 
X-Content-Type-Options, Referrer-Policy, Feature-Policy`

## Args
```
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Single target or file of newline seperated targets
  -c COOKIES, --cookies COOKIES
                        Cookies to use when forming a connection
  -o OUTFILE, --outfile OUTFILE
                        File to write 'result info' to; CSV format; defaults
                        to shredder.csv
  -x CUSTOM_HEADERS, --custom-headers CUSTOM_HEADERS
                        A semi-colon seperated list of custom headers to parse
                        for
```

## Example input: input.txt
```
https://google.com
https://github.com/pulls
https://old.reddit.com/r/programming/
```

## Example usage
`python3 headerShredder.py -t input.txt`

## Example output: shredder.csv
```
URL,X-XSS-Protection,X-Frame-Options,Content-Security-Policy,X-Content-Type-Options,Referrer-Policy,Feature-Policy
https://github.com/pulls,Yes,Yes,Yes,Yes,Yes,No
https://old.reddit.com/r/programming/,Yes,Yes,No,Yes,No,No
https://google.com,Yes,Yes,No,No,No,No
```

## Example with custom headers
`python3 headerShredder.py -t input.txt -x "basicauth;customvalue;etc"`
