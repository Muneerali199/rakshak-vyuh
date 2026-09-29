/** Shapes emitted by vyuh-core. Kept in step with crates/vyuh-core/src/posture.rs. */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Evidence = "observed" | "inferred";

export interface TransformAttribute {
  af_flags: number;
  attr_type: number;
  interpreted: string | null;
  raw: string;
}

export interface Transform {
  transform_type: number;
  type_name: string;
  transform_id: number;
  name: string;
  key_bits: number | null;
  block_bits: number | null;
  requirement: string | null;
  usable: boolean;
  discouraged: boolean;
  demoted: boolean;
  note: string | null;
  attributes: TransformAttribute[];
}

export interface Proposal {
  number: number;
  protocol_id: number;
  spi: string | null;
  transforms: Transform[];
}

export interface TrafficSelector {
  ts_type: number;
  protocol_id: number | null;
  start: string;
  end: string;
  start_port: number | null;
  end_port: number | null;
}

export type Payload =
  | { Sa: { proposals: Proposal[] } }
  | { Ke: { group_id: number } }
  | { Identification: { id_type: number; value: string } }
  | { Nonce: { bytes: number } }
  | { NonceIkev1: { bytes: number } }
  | { Auth: { method: number | null; raw_len: number } }
  | { Certificate: { cert_type: number; raw_len: number } }
  | { Notify: { protocol_id: number; notify_type: number; spi_size: number } }
  | { Delete: Record<string, never> }
  | { VendorId: { raw: string } }
  | { TrafficSelector: { selectors: TrafficSelector[]; initiator: boolean } }
  | { Encrypted: { len: number } }
  | { Opaque: { payload_type: number; len: number } };

export interface IkeMessage {
  version: "V1" | "V2";
  packet_index: number;
  src: string;
  dst: string;
  src_port: number;
  dst_port: number;
  initiator_spi: string;
  responder_spi: string;
  exchange_type: number;
  exchange_name: string;
  message_id: number;
  is_request: boolean;
  aggressive_mode: boolean;
  has_pfs_signal: boolean;
  selected_proposal: Proposal | null;
  offered_proposals: Proposal[];
  payloads: Payload[];
  identities_in_clear: string[];
  vendor_ids: string[];
  truncated: boolean;
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  standard: string;
  cwe: string | null;
  packet_index: number;
  src: string;
  dst: string;
  observed: string;
  remediation: string;
}

export interface RatedFinding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  standard: string;
  cwe: string | null;
  packet_index: number;
  src: string;
  dst: string;
  observed: string;
  remediation: string;
  evidence: Evidence;
  /** How many Security Associations or frames corroborated this finding. */
  occurrences: number;
}

export interface SaPosture {
  sa_id: string;
  src: string;
  dst: string;
  ike_version: string;
  exchanges_seen: string[];
  aggressive_mode: boolean;
  encryption: string | null;
  integrity: string | null;
  key_exchange: string | null;
  prf: string | null;
  key_bits: number | null;
  perfect_forward_secrecy: boolean | null;
  transport_or_tunnel: string | null;
  identities_in_clear: string[];
  vendor_ids: string[];
  strongest: string | null;
  downgrade_observed: boolean;
  /** The peer refused at least one attempt: it answered with a notification
   *  instead of an SA payload. The tunnel may still have been established on a
   *  later attempt, so this is not on its own a failure. */
  negotiation_rejected: boolean;
  /** Notification types the peer sent on a refused attempt. */
  rejection_notifies: number[];
  /** First packet folded into this record. */
  first_packet: number;
  /** Packet that carried the suite; 0 if none was ever seen. */
  suite_packet: number;
  score: number;
  grade: string;
  findings: RatedFinding[];
  quantum_exposure: number;
}

export interface Report {
  tool: string;
  version: string;
  capture: string;
  pcap_sha256: string;
  packets_examined: number;
  ike_messages: number;
  esp_flows: number;
  security_associations: SaPosture[];
  posture_score: number;
  grade: string;
  severity_counts: Record<string, number>;
  global_findings: RatedFinding[];
  blindspots: string[];
}

export interface LedgerEntry {
  sequence: number;
  canonical: string;
  payload_digest: string;
  previous: string;
  digest: string;
}

export interface Ledger {
  capture_sha256: string;
  tool: string;
  tool_version: string;
  entries: LedgerEntry[];
  head: string;
  intact: boolean;
}
