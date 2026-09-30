# Ethical Clearance Form

**Module:** IE3142 — DevOps Security
**Institution:** Sri Lanka Institute of Information Technology (SLIIT)
**Assessment:** Continuous Assessment — Building and Securing a DevSecOps Pipeline
**Group:** 4 members (Member 1–4, IDs listed in the technical report, Section 9)
**Date of declaration:** ____________________

---

## 1. Target application

| Item | Detail |
|---|---|
| Application | OWASP Juice Shop v20.2.0 |
| Licence | MIT |
| Why it is appropriate | Juice Shop is an application **deliberately built to be vulnerable** by the Open Web Application Security Project, specifically so that security techniques can be practised and assessed against it. It appears on the module's pre-vetted **Appendix A.1** list, so no further confirmation was required. |
| Source | Obtained from the project's own public release and used, unmodified, as the *vulnerable baseline*. |

## 2. Scope of testing

All testing was performed against **locally hosted instances** of the application running inside
Docker containers on the group's own machines:

- `http://localhost:3000` — the unmodified, vulnerable upstream build (the **baseline**).
- `http://localhost:3001` — the group's hardened build (the **fixed** target).

No system outside the group's own equipment was tested. No third-party service, no cloud
environment, and no network belonging to SLIIT or to any other party was scanned or attacked.

The only outbound request made by an exploit was the Server-Side Request Forgery proof of concept
(V3), which instructed the *local* baseline application to fetch a URL served by a listener the
group started on its **own loopback interface** (`127.0.0.1`). This was necessary to prove that the
request originated from inside the application's trust boundary. It did not touch any external
host.

## 3. Data

- The application was used with its **shipped demo data set** and with accounts the group created
  itself. No real personal data was entered, processed, or stored.
- No data was collected from, or about, any person other than the four group members.
- All databases are local SQLite files inside containers and were destroyed with the containers.

## 4. Declarations

Each member declares that:

1. **No unauthorised system was accessed.** Every target was a local container owned and operated
   by the group.
2. **No malicious code was created or distributed.** The proof-of-concept scripts in `poc/` are
   small, dependency-free Node programs whose only function is to reproduce a known vulnerability
   against a local target and to verify that the fix closes it. They are not wormable, not
   persistent, and not capable of affecting any host other than the one they are pointed at. They
   are published **only** as coursework evidence.
3. **No exploit technique was applied outside the assessment.** The techniques were learned and
   applied solely to complete this assignment.
4. **Vulnerabilities were remediated, not left exposed.** Every demonstrated flaw was fixed in the
   group's own codebase before submission. The vulnerable baseline is the *public upstream
   release*, not code the group wrote, so nothing new was made insecure by this work.
5. **No hard-coded secret is committed.** The RSA signing key used by the hardened build is
   generated locally by `scripts/generate-keys.sh`, is excluded by `.gitignore`, and is injected at
   runtime from HashiCorp Vault or a Docker secret. Gitleaks scans the full Git history on every
   push and the repository is verified clean.
6. **The group's own work.** Except where disclosed in Section 9 of the technical report, all
   analysis, code, and written material are the group's own. AI assistance is disclosed there in
   full, as the brief requires. No Juice Shop community write-up was copied into the report.
7. **Academic integrity.** The group understands that submitting work that is not its own, or that
   is undisclosed AI-generated, is an academic-integrity violation.

## 5. Signatures

| # | Name | Student ID | Role | Signature | Date |
|---|---|---|---|---|---|
| 1 | | IT21xxxxx | Lead engineer — application & containers | ______________________ | __________ |
| 2 | | IT21xxxxx | Security engineer — threat model | ______________________ | __________ |
| 3 | | IT21xxxxx | Security engineer — secure coding | ______________________ | __________ |
| 4 | | IT21xxxxx | DevOps engineer — CI/CD & secrets | ______________________ | __________ |

**Group leader (Member 1) confirmation:** I confirm that every member named above contributed to
the work and that all four signatures are genuine.

Signature: ______________________  Date: __________

---

## 6. For office use only

| | |
|---|---|
| Received by | ______________________ |
| Date | __________ |
| Approved / Not approved | ______________________ |
| Comments | ______________________ |
