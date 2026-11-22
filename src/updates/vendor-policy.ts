import type { VendorId } from "../types";

/**
 * Human-maintained affected ranges for vendor security statements that are not
 * fully represented by GitHub Security Advisories.
 *
 * Update this list only from an official vendor release, advisory, or blog post.
 * Record the source URL, the date the statement was checked, and the exact
 * affected range the vendor stated. Do not invent a range from a changelog tone.
 * A security-related release without a range is classified in code as a review
 * warning, not as a confirmed vulnerability.
 */
export interface ConfirmedAdvisory {
  id: string;
  vendorId: VendorId;
  url: string;
  summary: string;
  /** npm-style comparators understood by satisfiesRange. Versions inside the range are affected. */
  ranges: string[];
  verifiedOn: string;
  sourceNote: string;
}

export const VENDOR_POLICY: ConfirmedAdvisory[] = [
  {
    id: "btcpay-2026-08-lnd-macaroon",
    vendorId: "btcpayserver/btcpayserver",
    url: "https://blog.btcpayserver.org/security-advisory-btcpay-server-2-4-2/",
    summary:
      "BTCPay Server versions before 2.4.2, including 2.4.2 release candidates, contain the vulnerability fixed in 2.4.2. The vendor says LND credential theft is the exploited case and still asks every earlier version to update.",
    ranges: ["< 2.4.2"],
    verifiedOn: "2026-11-22",
    sourceNote:
      "Official BTCPay Server blog post published 2026-08-07, cross-checked with the v2.4.2 GitHub release. This does not say whether a particular server uses LND.",
  },
  {
    id: "btcpay-2026-11-incident",
    vendorId: "btcpayserver/btcpayserver",
    url: "https://blog.btcpayserver.org/btcpay-server-security-incident-2-4-1-and-earlier/",
    summary:
      "The November 2026 BTCPay Server incident affected 2.4.1 and earlier. The vendor reported no thefts against servers already on 2.4.2 or later. Updating a previously exposed server does not undo a compromise.",
    ranges: ["<= 2.4.1"],
    verifiedOn: "2026-11-22",
    sourceNote:
      "Official BTCPay Server blog post published 2026-11-02. Checked again on 2026-11-22. The watchdog reports version exposure only.",
  },
];

export function policyFor(vendorId: VendorId): ConfirmedAdvisory[] {
  return VENDOR_POLICY.filter((entry) => entry.vendorId === vendorId);
}
