export interface ContentScanResult {
  safe: boolean;
  reason?: string;
}

const UNSAFE_PATTERNS: ReadonlyArray<{
  pattern: RegExp;
  reason: string;
}> = [
  {
    pattern:
      /\b(?:ignore|disregard|override|bypass)\b.{0,100}\b(?:previous|prior|system|developer|safety)\b.{0,60}\b(?:instructions?|rules?|prompt)\b/is,
    reason: "instruction-override pattern",
  },
  {
    pattern: /<\s*\/?\s*(?:system|developer|assistant|tool)(?:\s|>)/i,
    reason: "reserved role tag",
  },
  {
    pattern:
      /\b(?:exfiltrate|upload|send)\b.{0,100}\b(?:credentials?|passwords?|tokens?|api[ _-]?keys?|private keys?)\b/is,
    reason: "credential-exfiltration pattern",
  },
  {
    pattern:
      /\b(?:curl|wget|invoke-webrequest)\b.{0,180}\b(?:\.ssh|id_rsa|credentials?|private[ _-]?key|api[ _-]?key)\b/is,
    reason: "command-based credential access pattern",
  },
];

const INVISIBLE_OR_BIDI_RE =
  /[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u;
const UNSAFE_CONTROL_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u;

export function scanPersistentContent(value: string): ContentScanResult {
  if (INVISIBLE_OR_BIDI_RE.test(value)) {
    return {
      safe: false,
      reason: "invisible or bidirectional control characters",
    };
  }

  if (UNSAFE_CONTROL_RE.test(value)) {
    return { safe: false, reason: "unsupported control characters" };
  }

  const normalized = value.normalize("NFKC");
  for (const candidate of UNSAFE_PATTERNS) {
    if (candidate.pattern.test(normalized)) {
      return { safe: false, reason: candidate.reason };
    }
  }

  return { safe: true };
}
