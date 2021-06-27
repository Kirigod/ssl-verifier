<div align="center">
  <br>
  <h1>ssl-verifier</h1>
  <p>
    <a href="https://www.npmjs.com/package/ssl-verifier"><img src="https://nodei.co/npm/ssl-verifier.png" alt="npm installnfo"/></a>
  </p>
</div>

## Table of contents

- [About](#about)
- [Installation](#installation)
- [Example Usage](#example-usage)
- [Links](#links)
- [Help](#help)

## About

ssl-verifier is a package that verifies SSL information from a URL.

## Installation

**[Node.js](https://nodejs.org) v14.16.1 or newer is recommended.**  

Install: `npm install ssl-verifier`


## Options

| Option             | Default | Description                                        |
| ------------------ | ------- | -------------------------------------------------- |
| method             | GET     | Can be HEAD too                                    |
| port               | 443     | Your SSL/TLS entry point                           |
| agent              | default | Default HTTPS agent with { maxCachedSessions: 0 }  |
| rejectUnauthorized | false   | Skips authorization by default                     |

## Example usage

```js
const SSL = require("ssl-verifier");

SSL.Info("https://github.com"/*, {port: 443, method: "GET"}*/).then(data => {
  
  console.log(data);
  
}).catch(error => {

  console.log(error);
  
});
```

## Response Example

```js
{
  subject: {
    commonName: "github.com",
    organization: "GitHub, Inc.",
    location: "San Francisco, California, US"
  },
  issuer: {
    commonName: "DigiCert High Assurance TLS Hybrid ECC SHA256 2020 CA1",
    organization: "DigiCert, Inc.",
    location: "US"
  },
  subjectAlternativeName: [ "github.com", "www.github.com" ],
  valid: true,
  validFrom: "Mar 25 00:00:00 2021 GMT",
  validTo: "Mar 30 23:59:59 2022 GMT",
  daysRemaining: 281,
  certificate: {
    OCSP: {
      url: [ "http://ocsp.digicert.com" ]
    },
    CA: {
      issuers: {
        url: [ "http://cacerts.digicert.com/DigiCertHighAssuranceTLSHybridECCSHA2562020CA1.crt" ]
      }
    }
  },
  bits: 256,
  modulus: undefined,
  exponent: undefined,
  publicKey: "<Buffer... 15 more bytes>",
  asn1Curve: "prime256v1",
  nistCurve: "P-256",
  fingerPrint: "84:63:B3:A9:29:12:CC:FD:1D:31:47:05:98:9B:EC:13:99:37:D0:D7",
  fingerPrint256: "0A:E3:84:BF:D4:DD:E9:D1:3E:50:C5:85:7C:05:A4:42:C9:3F:8E:01:44:5E:E4:B3:45:40:D2:2B:D1:E3:7F:1B",
  ExtendedKeyUsage: [ "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2" ],
  serialNumber: "0E8BF3770D92D196F0BB61F93C4166BE",
  raw: "<Buffer... 1240 more bytes>"
}
```

## Expected Errors

If a problem occurs in the process, one of these errors might be triggered.

`Invalid url` - `Invalid protocol` - `Invalid options` - `Invalid method` - `Invalid port` - `No certificate`<br>
`ENOTFOUND` - `EPROTO` - `ERR_INVALID_URL` - `ERR_SOCKET_BAD_PORT` - `ERR_INVALID_ARG_TYPE`

## Links

- [GitHub](https://github.com/Kirigod/ssl-verifier)
- [NPM](https://www.npmjs.com/package/ssl-verifier)

## Help

If you are experiencing problems, or you just need a nudge in the right direction, please do not hesitate to create a New Issue on [Github](https://github.com/Kirigod/ssl-verifier) repository.
