# Security policy

## Reporting a vulnerability

Please use the below process to report a vulnerability to the project:

Email:

1. Email the Mysten Labs Security Team: **security@mystenlabs.com**
    * Emails should contain:
        * description of the problem
        * precise and detailed steps (include screenshots) that created the
          problem
        * the affected version(s)
        * any possible mitigations, if known
2. You will receive a reply from one of the maintainers within 48 hours
   acknowledging receipt of the email.
3. You may be contacted by the team to further discuss the reported item.
   Please bear with us as we seek to understand the breadth and scope of the
   reported problem, recreate it, and confirm if there is a vulnerability
   present.

Please do not open public GitHub issues for suspected vulnerabilities.

## Scope notes

This crate is a thin wrapper: most of the cryptographic attack surface lives
in the vendored [mldsa-native] C library, which has its own upstream security
process. Reports about the C implementation itself should generally go
upstream; reports about this crate's FFI boundary, its build configuration,
its key/signature handling (zeroization, parsing, entropy plumbing), or its
packaging belong here.

[mldsa-native]: https://github.com/pq-code-package/mldsa-native
