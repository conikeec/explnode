# ExplNode 
# A web application seeded with vulnerabilities, rootkits, backdoors and data leaks

Explnode is a NodeJs based application that is seeded with vulnerable conditions (OWASP based, Business Logic Flaws, Rootkits and Data Leaks). Its main goal is to be an aid for security professionals to test with [Ocular](https://ocular.shiftleft.io), help web developers better understand the processes of securing web applications.

### Common Vulnerabilities

| File                                                                                              | Description                                                     |
| ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| [`dep-lodash.js`](https://github.com/conikeec/explnode/blob/master/vulnerabilities/dep-lodash.js) | Prototype Pollution Attack caused due to OSS dependency LogDash |
| [`exec.js`](https://github.com/conikeec/explnode/blob/master/vulnerabilities/exec.js)             | RCE Command Injection Exploit                                   |
| [`loop.js`](https://github.com/conikeec/explnode/blob/master/vulnerabilities/loop.js)             | Denial of Service Exploit                                       |
| [`nosqli.js`](https://github.com/conikeec/explnode/blob/master/vulnerabilities/nosqli.js)         | NoSql Injection Attack                                          |
| [`redirect.js`](https://github.com/conikeec/explnode/blob/master/vulnerabilities/redirect.js)     | Information Disclosure, Exfiltration Channel                    |
| [`redos.js`](https://github.com/conikeec/explnode/blob/master/vulnerabilities/redos.js)           | Regex Denial of Service Attack                                  |
| [`sqli.js`](https://github.com/conikeec/explnode/blob/master/vulnerabilities/sqli.js)             | Sql Injection Attack                                            |
| [`xss.js`](https://github.com/conikeec/explnode/blob/master/vulnerabilities/xss.js)               | Cross Site Scripting Attack                                     |
| [`xxe.js`](https://github.com/conikeec/explnode/blob/master/vulnerabilities/xxe.js)               | XXE Attack                                                      |

### Threat Modeling Queries
[`Queries`](https://github.com/conikeec/explnode/blob/master/ocular_notebook/README.md)

## :warning: Disclaimer

We do not take responsibility for the way in which any one uses this application. We have made the purposes of the application clear and it should not be used maliciously.
