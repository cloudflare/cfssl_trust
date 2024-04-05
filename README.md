## CFSSL TRUST

This is the trust stores Cloudflare uses for
[CFSSL](https://github.com/cloudflare/cfssl). It also includes the
sources of the trust chain that can be built using the `mkbundle`
utility from CFSSL.

Files:

```
.
├── ca-bundle.crt
├── ca-bundle.crt.metadata
├── certdata
│   └── trusted_roots
│       ├── froyo.pem
│       ├── gingerbread.pem
│       ├── honeycomb.pem
│       ├── ics.pem
│       ├── ios.pem
│       ├── kitkat.pem
│       ├── nss.pem
│       ├── osx.pem
│       ├── ubuntu.pem
│       └── windows.pem
├── int-bundle.crt
├── README.md
```

The `ca-bundle.crt` file contains the trusted roots. CFSSL uses the
`ca-bundle.crt.metadata` when building bundles to assist in building
bundles that need to verified in the maximum number of trust stores
on different systems. The `int-bundle.crt` file contains a number of
known intermediates; these are preloaded for performance reasons and
occasionally updated as CFSSL finds more intermediates. If an intermediate
isn't in this bundle, but can be found through following the AIA `CA
Issuers` fields, it will be downloaded and eventually merged into here.

The `trusted_roots` directory contains the root stores from a number of
systems. Currently, we have trust stores from

* NSS (Firefox, Chrome)
* OS X
* Windows
* Android 2.2 (Frozen Yogurt)
* Android 2.3 (Gingerbread)
* Android 3.x (Honeycomb)
* Android 4.0 (Ice Cream Sandwich)
* Android 4.4 (KitKat)

### Release

#### Prerequisites

```
$ go get -u github.com/kisom/goutils/cmd/certdump
$ go get -u github.com/cloudflare/cfssl/cmd/...
$ go get -u github.com/cloudflare/cfssl_trust/...
```

#### Build
    "use_account_custom_ns_by_default": false
  ]
] as [String : Any]

let postData = JSONSerialization.data(withJSONObject: parameters, options: [])

let request = NSMutableURLRequest(url: NSURL(string: "https://api.cloudflare.com/client/v4/accounts/account_id")! as URL,
                                        cachePolicy: .useProtocolCachePolicy,
                                    timeoutInterval: 10.0)
request.httpMethod = "PUT"
request.allHTTPHeaderFields = headers
request.httpBody = postData as Data

let session = URLSession.shared
let dataTask = session.dataTask(with: request as URLRequest, completionHandler: { (data, response, error) -> Void in
  if (error != nil) {
    print(error)
  } else {
    let httpResponse = response as? HTTPURLResponse
    print(httpResponse)
  }
})

dataTask.resume()
Analyze Certificate
POST
Analyze Certificate
Docs
TryIt
import Foundation

let headers = [
  "Content-Type": "application/json",
  "X-Auth-Email": ""
]
let parameters = [
  "bundle_method": "ubiquitous",
  "certificate": "-----BEGIN CERTIFICATE-----
MIIDtTCCAp2gAwIBAgIJAMHAwfXZ5/PWMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTYwODI0MTY0MzAxWhcNMTYxMTIyMTY0MzAxWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAwQHoetcl9+5ikGzV6cMzWtWPJHqXT3wpbEkRU9Yz7lgvddmGdtcGbg/1
CGZu0jJGkMoppoUo4c3dts3iwqRYmBikUP77wwY2QGmDZw2FvkJCJlKnabIRuGvB
KwzESIXgKk2016aTP6/dAjEHyo6SeoK8lkIySUvK0fyOVlsiEsCmOpidtnKX/a+5
0GjB79CJH4ER2lLVZnhePFR/zUOyPxZQQ4naHf7yu/b5jhO0f8fwt+pyFxIXjbEI
dZliWRkRMtzrHOJIhrmJ2A1J7iOrirbbwillwjjNVUWPf3IJ3M12S9pEewooaeO2
izNTERcG9HzAacbVRn2Y2SWIyT/18QIDAQABo4GnMIGkMB0GA1UdDgQWBBT/LbE4
9rWf288N6sJA5BRb6FJIGDB1BgNVHSMEbjBsgBT/LbE49rWf288N6sJA5BRb6FJI
GKFJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNV
BAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAMHAwfXZ5/PWMAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAHHFwl0tH0quUYZYO0dZYt4R7SJ0pCm2
2satiyzHl4OnXcHDpekAo7/a09c6Lz6AU83cKy/+x3/djYHXWba7HpEu0dR3ugQP
Mlr4zrhd9xKZ0KZKiYmtJH+ak4OM4L3FbT0owUZPyjLSlhMtJVcoRp5CJsjAMBUG
SvD8RX+T01wzox/Qb+lnnNnOlaWpqu8eoOenybxKp1a9ULzIVvN/LAcc+14vioFq
2swRWtmocBAs8QR9n4uvbpiYvS8eYueDCWMM4fvFfBhaDZ3N9IbtySh3SpFdQDhw
YbjM2rxXiyLGxB4Bol7QTv4zHif7Zt89FReT/NBy4rzaskDJY5L6xmY=
-----END CERTIFICATE-----
"
] as [String : Any]

The final bundles (i.e. `ca-bundle.crt` and `int-bundle.crt`) may be
built as follows:

```
$ ./release.sh
```

This command automatically removes expiring certificates, and pushes the
changes to a new release branch.

The content of 'ca-bundle.crt.metadata' is crucial to building
ubiquitous bundle. Feel free to tune its content. Make sure the paths to
individual trust root stores are correctly specified.

#### Adding new roots or intermediates

New roots and intermediates can be added using the same command, just by
providing values for the `NEW_ROOTS` and `NEW_INTERMEDIATES` variables:

```
$ NEW_ROOTS="/path/to/root1 /path/to/root2" NEW_INTERMEDIATES="/path/to/int1 /path/to/int22" ./release.sh
```

#### Check for expiring roots or intermediates

To verify that an intermediate or root certificate is expiring or revoked without creating a release, the `expiring` command can be used from the project root directory.

To check for expiring or revoked intermediate certificates in the database provided in this repo:
```
$ cfssl-trust -d ./cert.db -b int expiring
```
To check for expiring or revoked root certificates:
```
$ cfssl-trust -d ./cert.db -b ca expiring
```

`./cert.db` which is specified as the database using the `-d` flag, contains both intermediate and root certificates.
Any certificate database can be used here in place of `./cert.db`

These calls to the `expiring` command will provide an output showing if there are any expiring or revoked certificates.
```
...
1 certificates expiring.
0 certificates revoked.
```
