<p align="center">
    <img src="https://devanghacks.in/agneyastra/agneyastra_logo.png" alt="varunastra logo" width="200">
  <br>
</p>
<p align="center">
<a href="https://www.gnu.org/licenses/gpl-3.0.en.html/"><img src="https://img.shields.io/badge/license-GPL_3.0-_red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/JA3G3R/agneyastra"><img src="https://goreportcard.com/badge/github.com/JA3G3R/agneyastra"></a>
<a href="https://go.dev/blog/go1.22.5"><img src="https://img.shields.io/github/go-mod/go-version/JA3G3R/agneyastra"></a>
<a href="https://twitter.com/BhavarthKr"><img src="https://img.shields.io/twitter/follow/BhavarthKr.svg?logo=twitter"></a>
</p>
<p align="center">
  <a href="#installation-guide-for-agneyastra">Installation</a>
  <a href="#usage">Usage</a>
</p>


# agneyastra - A firebase Misconfiguration Detection Toolkit

Firebase, a versatile platform by Google, powers countless web and mobile applications with its extensive suite of services including real-time databases, authentication, cloud storage, and hosting. Its ubiquity and ease of use make it a popular choice among developers, but also a prime target for misconfigurations that can lead to significant security vulnerabilities.

Agneyastra, a mythological weapon bestowed upon by the Agni (fire) Dev (god) is a divine weapon associated with the fire element. Presenting Agneyastra, a cutting-edge tool designed to empower bug bounty hunters and security professionals with unparalleled precision in detecting Firebase misconfigurations. With its comprehensive checks covering all of Firebase services, a correlation engine and Secret Extraction, and automated report generation, Agneyastra ensures that no vulnerability goes unnoticed, turning the tides in your favor.

# 🔥 Agneyastra

Agneyastra is an advanced reconnaissance and exploitation tool designed to identify and report misconfigurations in Firebase services. Tailored for security professionals and bug bounty hunters, it automates checks for unauthorized **Read**, **Write**, and **Delete** access across various Firebase products and correlates findings with organizational data for higher precision and impact.

---

## 🚀 Features

- 🔍 **Automated Firebase Misconfiguration Scanning**
  - Checks for **Read**, **Write**, and **Delete** access in:
    - Firestore
    - Realtime Database
    - Storage Buckets

- 🧠 **Credential-Aware Access Simulation**
  - Uses credentials in increasing order of privilege to simulate real-world access patterns.
  - Starts with unauthenticated (public) access to detect outright exposed endpoints.

- 🧩 **Correlation Engine**
  - Optional but powerful module to determine whether a Firebase instance is likely associated with your target.
  - Accepts inputs like subdomains, acquisitions, team member profiles, and more.
  - Produces a confidence score to help prioritize targets.

- 🛠️ **Proof of Concept Generation (Coming Soon)**
  - Automatically create PoCs and remediation steps for responsible disclosure or internal reports.

---

## 🏗️ Installation

```bash
go install github.com/JA3G3R/agneyastra/cmd/agneyastra@latest
```

---

## ⚙️ Usage

Basic scan:
```bash
agneyastra --key <your-firebase-api-key> -all
```

Service Specific Scan (Does not try auth):
```bash
agneyastra bucket -a --key <your-firebase-api-key> 
```

Service Specific Scan (With Auth):
```bash
agneyastra bucket -a --key <your-firebase-api-key> --auth all
```


With correlation engine:
```bash
python agneyastra.py --key <your-firebase-api-key> -all  --pentest-data <your-pentest-data-file.json>
```

With Secret Extraction:
```bash
python agneyastra.py --key <your-firebase-api-key> -all  --secrets-extract
```

With Asset Extraction:
```bash
python agneyastra.py --key <your-firebase-api-key> -all  --assets-extract 
```



Show all options:
```bash
python agneyastra.py --help
```

---

## File Formats

### config.yaml

This file is present at the path `~/.agneyastra/config.yaml`, and looks like:
```
general:
  debug: false

services:
  auth:
    send-link:
      email: "<your-email>"
    custom-token:
      token: "<custom-jwt-token>"
    signup:
      email: "<custom-email>"
      password: "<custom-password>"
  bucket:
    upload:
      filename: "<path-to-file-for-testing-bucket-upload>"
```
You can either edit this file, or provide a file of your choice using the flag `--config`

### template.html

This file is present at the path `~/.agneyastra/template.html` and is used to generate the html report. To create a custom template, make sure that you use the same variables for placeholders. Either edit this file or provide your own using the flag `--template-file`


---

## 🧩 Supported Services

| Firebase Service     | Read | Write | Delete |
|----------------------|------|-------|--------|
| Firestore            | ✅   | ✅    | ✅     |
| Realtime Database    | ✅   | ✅    | ✅     |
| Storage Buckets      | ✅   | ✅    | ✅     |


---

## 🔐 Authentication Strategy

The tool obtains authentication token using the following authentication methods:
1. **Public (No Authentication)**
2. **Anonymous Authentication**
3. **New User Sign Up**
4. **Login Credentials** *(if provided by the user)*
5.  **Custom JWT** *(if provided by the user)*

The tool also checks whether the send sign-in link option is enabled in the project

This enables realistic privilege escalation and vulnerability identification.

---

## 📊 Reporting

Output formats supported:
- JSON 
- HTML

Reports include:
- Summary of vulnerabilities
- Correlation confidence (if enabled)
- Remediation suggestions *(planned)*

---

## 📦 Requirements

- Golang (1.22.0+)

---

## 🛡️ Disclaimer

Agneyastra is intended **strictly for ethical testing, educational use, or environments you have explicit permission to test**. Unauthorized scanning of Firebase endpoints may be illegal and unethical. Use responsibly.

---

## 🧑‍💻 Contributing

Contributions are welcome! Open an issue or pull request to discuss ideas or bugs.

---


## 💬 Contact

Created by [Bhavarth Karmarkar](https://github.com/JA3G3R)  
For inquiries or collaborations: bhavarth1905kr@gmail.com
---

## 🧪 Example Output


```
./agneyastra --key AIzaSyBv_y636JW_LYBcUQ7rN0b9Wukzop_gVEI --all
2024/11/22 23:17:40 Checking all services for misconfigurations
2024/11/22 23:17:42 Sign-in link sent to email: bhavarth1905kr@gmail.com
2024/11/22 23:17:44 Checking public read access. Dump directory: 
2024/11/22 23:17:50 Running all firebase firestore misconfiguration checks
2024/11/22 23:18:00 Running all firebase rtdb misconfiguration checks
Final Report:
{
  "api_keys": [
    {
      "api_key": "AIzaSyBv_y636JW_LYBcUQ7rN0b9Wukzop_gVEI",
      "correlation_score": 0,
      "auth": {
        "anon-auth": {
          "Vulnerable": "vulnerable:true",
          "Error": "",
          "AuthType": "",
          "VulnConfig": "",
          "Remedy": "Disable Anonymous Authentication",
          "Details": {
            "expiresIn": "3600",
            "idToken": "redacted",
            "localId": "3S1VMdFs2PVoISOrNxr8zL4akhs2",
            "refreshToken": "redacted"
          }
        },
        "custom-token-login": {
          "Vulnerable": "error",
          "Error": "failed to log in with custom token, status code: 400",
          "AuthType": "",
          "VulnConfig": "",
          "Remedy": "",
          "Details": null
        },
        "send-signin-link": {
          "Vulnerable": "vulnerable:true",
          "Error": "",
          "AuthType": "",
          "VulnConfig": "Send Sign in Link enabled in Firebase project.",
          "Remedy": "Disable Send Sign in Link from Firebase Console",
          "Details": {
            "email": "bhavarth1905kr@gmail.com"
          }
        },
        "signup": {
          "Vulnerable": "error",
          "Error": "failed to sign up with email/password, status code: 400",
          "AuthType": "",
          "VulnConfig": "",
          "Remedy": "",
          "Details": null
        }
      },
      "services": {
        "bucket": {
          "delete": {
            "104159166443": {
              "Vulnerable": "vulnerable:true",
              "Error": "",
              "AuthType": "",
              "VulnConfig": "allow delete: if true; // Allows public delete access to storage objects.",
              "Remedy": "Disable public delete access: 'allow delete: if false;'.",
              "Details": {
                "status_code": ""
              }
            },
            "agneyastra-testing2": {
              "Vulnerable": "vulnerable:true",
              "Error": "",
              "AuthType": "anon",
              "VulnConfig": "allow delete: if request.auth == null; // Permits unauthenticated users to delete storage objects.",
              "Remedy": "Restrict deletes to authenticated users: 'allow delete: if request.auth != null;'.",
              "Details": {
                "status_code": "404"
              }
            }
          },
          "read": {
            "104159166443": {
              "Vulnerable": "vulnerable:false",
              "Error": "",
              "AuthType": "public",
              "VulnConfig": "",
              "Remedy": "",
              "Details": {
                "Contents": {
                  "prefixes": null,
                  "items": null
                }
              }
            },
            "agneyastra-testing2": {
              "Vulnerable": "vulnerable:true",
              "Error": "",
              "AuthType": "anon",
              "VulnConfig": "allow read: if request.auth == null; // Allows unauthenticated access to storage objects.",
              "Remedy": "Restrict to authenticated users: 'allow read: if request.auth != null;'.",
              "Details": {
                "Contents": {
                  "prefixes": {
                    "testing/": {
                      "prefixes": {
                        "testing/inner-folder/": {
                          "prefixes": {},
                          "items": [
                            {
                              "name": "testing/inner-folder/burpcert.der",
                              "bucket": "agneyastra-testing2.appspot.com"
                            }
                          ]
                        }
                      },
                      "items": [
                        {
                          "name": "testing/2",
                          "bucket": "agneyastra-testing2.appspot.com"
                        }
                      ]
                    }
                  },
                  "items": [
                    {
                      "name": "1",
                      "bucket": "agneyastra-testing2.appspot.com"
                    },
                    {
                      "name": "firebase.html",
                      "bucket": "agneyastra-testing2.appspot.com"
                    },
                    {
                      "name": "poc.txt",
                      "bucket": "agneyastra-testing2.appspot.com"
                    }
                  ]
                }
              }
            }
          },
          "write": {
            "104159166443": {
              "Vulnerable": "vulnerable:unknown",
              "Error": "",
              "AuthType": "",
              "VulnConfig": "",
              "Remedy": "",
              "Details": {
                "status_code": "404"
              }
            },
            "agneyastra-testing2": {
              "Vulnerable": "vulnerable:true",
              "Error": "",
              "AuthType": "anon",
              "VulnConfig": "allow write: if request.auth == null; // Allows unauthenticated access to write storage objects.",
              "Remedy": "Restrict to authenticated users: 'allow write: if request.auth != null;'.",
              "Details": {
                "status_code": "200"
              }
            }
          }
        },
        "firestore": {
          "delete": {
            "104159166443": {
              "Vulnerable": "error",
              "Error": "bad request error in 2nd request",
              "AuthType": "",
              "VulnConfig": "",
              "Remedy": "",
              "Details": null
            },
            "agneyastra-testing2": {
              "Vulnerable": "vulnerable:true",
              "Error": "",
              "AuthType": "anon",
              "VulnConfig": "allow delete: if request.auth == null; // Permits unauthenticated users to delete storage objects.",
              "Remedy": "Restrict deletes to authenticated users: 'allow delete: if request.auth != null;'.",
              "Details": null
            }
          },
          "read": {
            "104159166443": {
              "Vulnerable": "error",
              "Error": "bad request error in 2nd request",
              "AuthType": "",
              "VulnConfig": "",
              "Remedy": "",
              "Details": null
            },
            "agneyastra-testing2": {
              "Vulnerable": "vulnerable:false",
              "Error": "",
              "AuthType": "",
              "VulnConfig": "",
              "Remedy": "",
              "Details": null
            }
          },
          "write": {
            "104159166443": {
              "Vulnerable": "error",
              "Error": "bad request error in 2nd request",
              "AuthType": "",
              "VulnConfig": "",
              "Remedy": "",
              "Details": null
            },
            "agneyastra-testing2": {
              "Vulnerable": "vulnerable:true",
              "Error": "",
              "AuthType": "anon",
              "VulnConfig": "allow write: if request.auth == null; // Allows unauthenticated access to write storage objects.",
              "Remedy": "Restrict to authenticated users: 'allow write: if request.auth != null;'.",
              "Details": null
            }
          }
        },
        "rtdb": {
          "delete": {
            "104159166443": {
              "Vulnerable": "vulnerable:true",
              "Error": "",
              "AuthType": "anon",
              "VulnConfig": "allow delete: if request.auth == null; // Permits unauthenticated users to delete storage objects.",
              "Remedy": "Restrict deletes to authenticated users: 'allow delete: if request.auth != null;'.",
              "Details": {
                "rtdb_url": "https://104159166443-default-rtdb.firebaseio.com/agneyastrapocBui7Cl.json",
                "status_code": "404"
              }
            },
            "agneyastra-testing2": {
              "Vulnerable": "vulnerable:false",
              "Error": "",
              "AuthType": "",
              "VulnConfig": "",
              "Remedy": "",
              "Details": {
                "rtdb_url": "https://agneyastra-testing2-default-rtdb.firebaseio.com/agneyastrapocBui7Cl.json",
                "status_code": "401"
              }
            }
          },
          "read": {
            "agneyastra-testing2": {
              "Vulnerable": "vulnerable:false",
              "Error": "",
              "AuthType": "",
              "VulnConfig": "",
              "Remedy": "",
              "Details": {
                "rtdb_url": "https://agneyastra-testing2-default-rtdb.firebaseio.com/.json",
                "status_code": ""
              }
            }
          },
          "write": {
            "agneyastra-testing2": {
              "Vulnerable": "vulnerable:false",
              "Error": "",
              "AuthType": "",
              "VulnConfig": "",
              "Remedy": "",
              "Details": {
                "rtdb_url": "https://agneyastra-testing2-default-rtdb.firebaseio.com/agneyastrapoc5WGiNY.json",
                "status_code": ""
              }
            }
          }
        }
      },
      "secrets": null
    }
  ]
}
```
