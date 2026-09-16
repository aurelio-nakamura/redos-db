export type Complexity = "quadratic" | "cubic" | "exponential";
export type EntryType = "cve" | "classic";
export type FixType = "regex-rewrite" | "algorithm-change" | "guidance";

export interface Attack {
  prefix: string;
  pad: string;
  suffix: string;
  sizes?: number[];
}

export interface Fix {
  type: FixType;
  summary: string;
  patched_regex?: string | null;
  commit?: string | null;
}

export interface VerificationPoint {
  input_length: number;
  pumps: number;
  ms: number | null;
  timed_out: boolean;
}

export interface Verification {
  engine: string;
  benign_ms: number;
  curve: VerificationPoint[];
  empirical_class: string;
  class_agrees: boolean;
}

export interface Entry {
  id: string;
  name: string;
  type: EntryType;
  cve?: string | null;
  ghsa?: string | null;
  cwe?: string | null;
  ecosystem: string;
  engine?: "javascript" | "python";
  package?: string | null;
  affected?: string | null;
  patched?: string | null;
  published?: string | null;
  discovered_by?: string | null;
  regex: string;
  flags: string;
  complexity: Complexity;
  attack: Attack;
  benign: string;
  fix: Fix;
  description: string;
  references: string[];
  visualize: string;
  verification?: Verification;
}

export const entries: Entry[];
export const count: number;
export const countsByType: Record<string, number>;
export const countsByComplexity: Record<string, number>;
export function byId(id: string): Entry | null;
export function filter(opts?: { type?: EntryType; complexity?: Complexity; ecosystem?: string }): Entry[];
export function attackString(entry: Entry, n: number): string;
