import { Entry } from '../index';

export interface InstalledDep {
  ecosystem: 'npm' | 'pypi' | string;
  name: string;
  version: string;
}

export interface Finding {
  package: string;
  version: string;
  ecosystem: string;
  id: string;
  cve: string | null;
  ghsa: string | null;
  complexity: string;
  affected: string;
  patched: string | null;
  summary: string;
  reproduction: string;
}

export interface AuditResult {
  dir: string;
  scanned: { npm: number; pypi: number };
  installed: InstalledDep[];
  findings: Finding[];
}

export function auditProject(dir: string | undefined, entries: Entry[]): AuditResult;
export function matchInstalled(installed: InstalledDep[], entries: Entry[]): Finding[];
export function collectNpm(dir: string): InstalledDep[];
export function collectPip(dir: string): InstalledDep[];
export function parsePipFreeze(text: string): InstalledDep[];
