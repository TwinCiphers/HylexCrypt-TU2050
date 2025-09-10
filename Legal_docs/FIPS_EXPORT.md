# FIPS / Export caveats and guidance (for Apache-2.0 project)

This file outlines practical caveats and guidance for projects that include
cryptographic functionality. It is NOT legal advice; consult legal counsel
for binding guidance.

## FIPS (Federal Information Processing Standards)
- The Apache-2.0 license does not make the code "FIPS-validated". FIPS validation
  is a formal certification process for cryptographic modules (e.g. OpenSSL,
  cryptographic libraries) by NIST.
- If you require FIPS-compliant operation for a government contract:
  - Use a FIPS-validated cryptographic module (e.g., vendor-provided module).
  - Ensure the module is called/used in a way that preserves FIPS mode (often requires
    building/running under special flags or OS-level policy).
  - Document the cryptographic boundaries and give a clear SBOM (Software Bill Of Materials)
    showing which components are FIPS-validated.
- Python libraries like `cryptography` can be used with FIPS-validated backends in some
  environments, but the default Python distribution is usually **not** FIPS-validated.

## Export controls (cryptography)
- Cryptographic software may be subject to export controls in some jurisdictions
  (for example, the U.S. Export Administration Regulations — EAR).
- If you intend to distribute this software internationally, consider:
  - The countries you will ship to (some countries are subject to embargoes).
  - Whether additional paperwork, license exceptions, or classification is required.
  - If the software will be used for military/weapon systems (special rules may apply).
- A few practical steps:
  - Maintain an SBOM and list of cryptographic primitives used.
  - Consult export control counsel for your target jurisdictions before large-scale distribution.
  - Add an `EXPORT_COMPLIANCE.md` and require recipients to confirm compliance as part of procurement.

## Procurement / Government use checklist
- Provide SBOM and dependency license list.
- Provide documented runtime/configuration steps to enable FIPS mode if required.
- Provide signed release artifacts (GPG signatures).
- Provide security contact (see `SECURITY.md`).
- Document data handling and key storage guidance (do NOT pass secrets on CLI in multi-user environments).

## Disclaimer
This is guidance only. For procurement or legal compliance, obtain counsel. Export control violations can carry serious penalties.

# FIPS 140-3 Compliance Notice

This project implements and uses cryptographic algorithms, but it is **not certified** under the
U.S. Federal Information Processing Standard (**FIPS 140-3**) or any equivalent national scheme.

## What this means
- The software may include algorithms that are **FIPS-approved** (such as AES, SHA-2, SHA-3, and HMAC).
- However, unless a module is formally validated by **NIST’s Cryptographic Module Validation Program (CMVP)**,
  it **cannot be claimed as FIPS-certified**.
- Therefore, this project **must not be represented** as "FIPS-compliant" or "FIPS-validated".

## Government and Enterprise Usage
- U.S. Government agencies and contractors that require FIPS 140-3 validated software
  **cannot rely on this project alone** without using a validated crypto library.
- Enterprises subject to regulatory requirements (e.g., HIPAA, FedRAMP, CJIS) must integrate this
  project with a **FIPS 140-3 validated cryptographic module** to meet compliance obligations.

## Developer Recommendations
- If you intend to deploy this project in regulated environments:
  - Use a FIPS-certified crypto backend (e.g., OpenSSL in FIPS mode, BoringSSL FIPS, or AWS-LibCrypto-FIPS).
  - Do not advertise compliance without official certification.
  - Consider seeking validation if broad government adoption is a goal.

## Export Caveats
- Even without FIPS validation, cryptography in this project may be subject to **export control laws**
  (see `EXPORT_COMPLIANCE.md` for details).
- This project is intended for **civilian and educational use** and is not specifically designed for
  military applications.

---

**Summary:**  
This project uses strong cryptography but is **not FIPS 140-3 validated**.  
Users are responsible for ensuring compliance with their own regulatory requirements.
