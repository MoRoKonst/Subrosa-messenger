# Software Support & Maintenance Agreement

**This Agreement** is entered into as of **[Effective Date]** by and between:

**Provider:** [Your Full Name], an independent contractor ("Provider")
Contact: [your email]

and

**Client:** [Client Firm / Individual Name], of [Client Address] ("Client")
Contact: [client email]

Provider and Client are each a "Party" and together the "Parties."

---

## 1. Background

Subrosa is an open-source, self-hosted encrypted messaging system (the "Software"), available under its published open-source license. The Software runs on infrastructure owned and controlled by the Client. This Agreement covers the support and maintenance services the Provider offers in relation to the Client's deployment of the Software. It does not transfer ownership of the Software, the Client's server, or the Client's data.

---

## 2. Services

During the term of this Agreement, the Provider will provide the following services (the "Services") according to the plan selected in **Schedule A**:

**2.1 Support.** The Provider will respond to the Client's support requests ("tickets") submitted by email within the response time defined in Schedule A. Response time refers to the Provider's initial reply, not to guaranteed resolution.

**2.2 Security Maintenance.** The Provider will inform the Client of relevant security updates to the Software and assist the Client in applying them to the Client's deployment.

**2.3 Deployment Assistance.** The Provider will assist the Client with deployment, configuration, and updates of the Software to the extent described in the selected plan.

**2.4 Scope.** The Services cover the Software only. They do not include support for the Client's hardware, network, operating system, cloud account, or any third-party software, except as incidental to deploying the Software.

---

## 3. Infrastructure and Data Ownership

**3.1** All infrastructure on which the Software runs — including any server, cloud account, domain, or storage — is owned and controlled by the **Client**. Where the Provider is granted access to operate or maintain the deployment, such access is limited to the scope necessary to perform the Services and may be revoked by the Client at any time.

**3.2** The Client is the sole owner and controller of all data processed or stored by the Client's deployment of the Software ("Client Data"). The Provider does not own, control, warehouse, or require access to Client Data in order to operate the Software.

**3.3** The Provider is **not responsible for the Client Data**, including its security, availability, backup, retention, loss, or disclosure. Responsibility for Client Data, and for lawful use of the Software, rests solely with the Client.

**3.4** Because the Software is end-to-end encrypted and self-hosted, the Provider has no technical ability to access the content of the Client's communications.

---

## 4. Security Model Acknowledgment

**4.1** The Software's threat model, cryptographic design, and — critically — its **known limitations** are documented in the Software's published Security Model (`SECURITY.md`), including a numbered "Known Limitations" section that the Provider maintains and updates as new limitations are identified or existing ones are resolved. The Client acknowledges having received and read that document, as of the version dated **[Date / commit hash]**, prior to executing this Agreement.

**4.2** Without limiting the generality of 4.1, the Client specifically acknowledges the following, in plain language:

- The Software provides strong protection for message **content** (end-to-end encryption, including post-quantum protection), but cannot, and does not claim to, eliminate every metadata exposure in every situation. Some information — such as who is registered on a server and when devices connect — is inherently visible to whoever operates that server.
- **Call signaling (audio/video call setup) is not anonymized from the server operator**, by deliberate design, to keep calls reliable — the operator can see who is calling whom and when, though not the call's audio/video content. Text messages, images, files, and group messages are anonymized from the server once an anonymous token pool is established with a contact, subject to the residual limitations documented in `SECURITY.md`.
- The custom anonymous-routing and metadata-protection mechanisms described in `SECURITY.md` are original protocol-design work by the Provider, not implementations of an independently peer-reviewed anonymity standard, and have not been independently audited as of the Effective Date.
- No security system, including this one, can defend against every conceivable threat model. The Client is solely responsible for evaluating whether the Software's actual, documented security properties are adequate for the Client's specific use case, professional obligations (e.g. privilege, regulatory duties), and risk tolerance — including by commissioning independent security review where the Client's use case warrants it.
- If the Client selects a Managed plan, the Provider will have operational access to the Client's infrastructure as described in Section 3 and, as a consequence of the call-signaling limitation above, will be able to observe call metadata (though not call content or the content of any other message type) for calls made through that deployment.

**4.3** The Client's initials below constitute specific acknowledgment of 4.1 and 4.2, separate from and in addition to the Client's signature at the end of this Agreement. This acknowledgment is a statement of informed consent, not a warranty or representation by the Provider beyond what is stated in Section 9 (Warranty Disclaimer).

Client initials acknowledging this Section 4: ______

---

## 5. Fees and Payment

**5.1** The Client will pay the fees for the selected plan as set out in Schedule A.

**5.2** Fees are billed [monthly / annually] in advance via [payment platform / invoice].

**5.3** Fees are exclusive of any taxes, which, if applicable, are handled by the payment platform or the responsible Party as required by law.

---

## 6. Term and Termination

**6.1** This Agreement begins on the Effective Date and continues for the billing period selected, renewing automatically unless either Party gives [14] days' written notice before the end of the current period.

**6.2** Either Party may terminate this Agreement for material breach if the breach is not cured within [14] days of written notice.

**6.3** On termination, the Provider's access to the Client's infrastructure (if any) ends, and the Client's deployment of the Software continues to operate independently. The open-source Software is unaffected by termination.

---

## 7. Confidentiality

Each Party will keep confidential any non-public information disclosed by the other Party in connection with this Agreement and use it only to perform this Agreement. This obligation survives termination.

---

## 8. Intellectual Property

The Software is provided under its open-source license, which governs all rights to use, modify, and distribute it. Nothing in this Agreement restricts the Client's rights under that license. This Agreement covers Services only, not a license to the Software.

---

## 9. Warranty Disclaimer

The Services are provided on a "reasonable efforts" basis. Except as expressly stated in this Agreement, the Services and the Software are provided **"as is"**, without warranties of any kind, whether express or implied, including any implied warranty of merchantability, fitness for a particular purpose, or non-infringement. The Provider does not warrant that the Software will be uninterrupted, error-free, or immune to every possible attack.

---

## 10. Limitation of Liability

**10.1** To the maximum extent permitted by law, the Provider will not be liable for any indirect, incidental, special, consequential, or punitive damages, or for any loss of data, loss of profits, or loss arising from the disclosure, unavailability, or misuse of Client Data.

**10.2** The Provider's total aggregate liability under this Agreement, for any cause, will not exceed the total fees paid by the Client to the Provider in the **[three (3)] months** preceding the event giving rise to the claim.

**10.3** Nothing in this Agreement excludes liability that cannot be excluded by law.

---

## 11. Independent Contractor

The Provider is an independent contractor. This Agreement does not create an employment, partnership, agency, or joint venture relationship between the Parties.

---

## 12. Governing Law

This Agreement is governed by the laws of [jurisdiction — e.g. the Client's country/state]. Any dispute will be resolved in the courts of that jurisdiction.

---

## 13. Entire Agreement

This Agreement, together with Schedule A, is the entire agreement between the Parties and supersedes all prior discussions. Any amendment must be in writing and signed by both Parties.

---

## Signatures

**Provider**

Name: ______________________________
Signature: _________________________
Date: ______________________________

**Client**

Name: ______________________________
Title: _____________________________
Signature: _________________________
Date: ______________________________

---

## Schedule A — Selected Plan

| Item | Detail |
|---|---|
| Plan | [ Solo / Firm / Managed ] |
| Monthly fee | [ $199 / $499 / $999+ ] |
| Billing cycle | [ Monthly / Annual ] |
| Support response time | [ 48h / 24h ] |
| Instances supported | One (1) |
| Designated Client administrator | [ name / email ] |
| Managed operation (if applicable) | [ Yes — scoped access to Client's cloud account / No ] |

---

*This is a plain-language template for a support and maintenance arrangement between an independent contractor and a small client. It is not legal advice. For higher-value engagements, or clients in strict regulatory environments, consider having it reviewed by a qualified lawyer in the relevant jurisdiction.*
