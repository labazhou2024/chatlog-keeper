# Disclaimer

English · [中文](DISCLAIMER.zh.md)

## 1. What this project is

This is an **open-source project for learning and research**, intended to help
users **export and back up the local chat history of their own account**, for
**personal preservation, nostalgia, and archiving** — embodying the principle
*"my data, my control."*

## 2. Boundaries of use (please follow them)

1. For **learning, research, and personal backup** only.
2. **Strictly limited to data belonging to the user's own account and stored
   locally on the user's own device.** Using it to export, access, or process
   **other people's** data is strictly prohibited.
3. All processing happens **entirely on the local device**. This project
   **never uploads, collects, or transmits** any user data — there is no network
   code in the decryption path.
4. Users are **solely responsible** for ensuring their use complies with all
   applicable laws and with the relevant Terms of Service (WeChat / QQ, etc.).
5. The developer assumes **no liability** for any direct or indirect consequence
   of use.
6. Output is provided **without warranty** of completeness or accuracy and
   **must not be used as legal or forensic evidence**, nor for any purpose beyond
   learning, research, and personal backup.
7. If any rights holder believes this project is problematic, please reach out
   via an issue; the developer will **cooperate in good faith**.
8. **Downloading, cloning, or using this project means you have read and agree to
   all of the above.**

## 3. Notes on the legality of "exporting your own data"

> ⚠️ The following is an objective summary of public information, **for reference
> only; it does not constitute legal advice**. Consult a qualified lawyer for your
> specific situation. Information compiled as of June 2026.

This project's core use case is **a user exporting their own account's chat
history, on their own device, with their own key.** For that scenario:

- **Data portability** — China's Personal Information Protection Law (PIPL),
  Art. 45, grants individuals the right to access and copy their personal
  information, and to request its transfer where conditions are met. A user
  preserving and backing up their own chat history has a legitimate basis (the
  implementing rules are still maturing).
- **Reverse-engineering exception** — China's Regulations on the Protection of
  Computer Software, Art. 17, recognize room for fair use and reverse
  engineering for the purpose of studying the ideas and principles embodied in
  software and for interoperability.
- **Terms of Service ≠ national law** — A platform's "no reverse engineering"
  clause governs the **contractual** relationship between user and platform
  (breach may lead to platform-level action such as account suspension); this is
  a different layer from whether **national law** is violated. China's
  Cybersecurity Law and Data Security Law mainly target intruding into
  **someone else's** system or stealing **someone else's** data without
  authorization — elements ("someone else's system", "without authorization")
  that are hard to establish when processing **your own data, your own account,
  on your own device**.
- **U.S. DMCA §1201 and precedent** — In the U.S., 17 U.S.C. §1201 is the
  anti-circumvention provision. But in the 2020 youtube-dl case, after the
  project was taken down on §1201 grounds, the EFF argued that accessing content
  a user is already authorized to access, in an authorized manner, is not
  "circumvention"; GitHub **reinstated** it and **tightened its review of §1201
  takedowns, stating it would favor developers in ambiguous cases**. "Accessing
  data you are authorized to access" has a strong defense under §1201.
- **Status quo** — As of this writing, there is **no known criminal or civil
  court judgment against the author of any "personal chat-history export tool"**;
  such matters have stayed at the level of platform takedown requests.

In short: a chat-history export-and-backup tool that is **limited to the user's
own account, runs purely locally, and never transmits anything** carries a
**relatively low risk of actual legal violation**; the main thing for a user to
keep in mind is the **possible breach of a platform's Terms of Service**. Please
make your own judgment, with the above in mind, and take responsibility for your
own use.

## 4. For developers and distributors

- Released under the **MIT License** — permissive and free for anyone to use.
- This project deliberately does **not** ship a one-click prebuilt installer and
  is **not** published to PyPI or other large distribution channels — it exists
  as **source code / a reference implementation** for those who need it to obtain
  and audit themselves.
- We respect all parties' rights. If any rights holder objects, please contact us
  via an issue and we will communicate and cooperate in good faith.
