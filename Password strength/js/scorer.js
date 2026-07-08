/**
 * @module scorer
 * @description ES6 module for calculating a composite password strength score
 * based on length, charset diversity, dictionary safety, pattern safety,
 * and brute-force entropy.
 */

// ─── Label / Emoji lookup table (ordered ascending by threshold) ─────────────
const STRENGTH_TIERS = [
  { ceiling: 39,  label: 'Very Weak',   emoji: '❌' },
  { ceiling: 59,  label: 'Weak',        emoji: '⚠️' },
  { ceiling: 74,  label: 'Moderate',    emoji: '🟡' },
  { ceiling: 89,  label: 'Strong',      emoji: '✅' },
  { ceiling: 100, label: 'Very Strong', emoji: '🔒' },
];

// ─── Individual scoring helpers ──────────────────────────────────────────────

/**
 * Score the password length (max 35 pts).
 *
 * @param {number} length - The password length in characters.
 * @returns {{ points: number, max: number, detail: string }}
 */
function scoreLength(length) {
  let points;
  let detail;

  if (length >= 16) {
    points = 35;
    detail = `Length ${length} (≥16): full marks`;
  } else if (length >= 12) {
    points = 25;
    detail = `Length ${length} (12-15): good length`;
  } else if (length >= 8) {
    points = 15;
    detail = `Length ${length} (8-11): minimum acceptable`;
  } else {
    points = 0;
    detail = `Length ${length} (<8): too short`;
  }

  return { points, max: 35, detail };
}

/**
 * Score charset diversity (max 20 pts, +5 per charset used).
 *
 * @param {{ lowercase: boolean, uppercase: boolean, digits: boolean, symbols: boolean }} charsets
 * @returns {{ points: number, max: number, detail: string }}
 */
function scoreCharset(charsets) {
  const categories = ['lowercase', 'uppercase', 'digits', 'symbols'];
  const used = categories.filter((c) => charsets[c]);
  const points = used.length * 5;
  const detail =
    used.length === 0
      ? 'No recognised character sets'
      : `Uses ${used.join(', ')} (${used.length}/4)`;

  return { points, max: 20, detail };
}

/**
 * Score dictionary safety (max 20 pts).
 *
 * @param {{ found: boolean, matches: Array }} dictionary
 * @returns {{ points: number, max: number, detail: string }}
 */
function scoreDictionary(dictionary) {
  if (!dictionary.found) {
    return { points: 20, max: 20, detail: 'No dictionary words detected' };
  }

  const matchList = dictionary.matches.map((m) =>
    typeof m === 'string' ? m : m.word ?? m.match ?? String(m),
  );
  const preview = matchList.slice(0, 3).join(', ');
  const detail =
    matchList.length > 3
      ? `Dictionary hits: ${preview}, … (${matchList.length} total)`
      : `Dictionary hits: ${preview}`;

  return { points: 0, max: 20, detail };
}

/**
 * Score pattern safety (max 15 pts).
 *
 * Severity classification:
 *  - "high" or "critical" → worst tier  → 0 pts
 *  - only "low"           → mid tier    → 10 pts
 *  - no patterns at all   → best tier   → 15 pts
 *
 * @param {Array<{ severity?: string }>} patterns
 * @returns {{ points: number, max: number, detail: string }}
 */
function scorePatterns(patterns) {
  if (!patterns || patterns.length === 0) {
    return { points: 15, max: 15, detail: 'No predictable patterns detected' };
  }

  const hasHighOrCritical = patterns.some((p) => {
    const sev = (p.severity ?? '').toLowerCase();
    return sev === 'high' || sev === 'critical';
  });

  if (hasHighOrCritical) {
    return {
      points: 0,
      max: 15,
      detail: `High/critical severity pattern(s) found (${patterns.length} total)`,
    };
  }

  // Only low-severity patterns remain
  return {
    points: 10,
    max: 15,
    detail: `Only low severity pattern(s) found (${patterns.length} total)`,
  };
}

/**
 * Score the brute-force entropy bonus (max 10 pts).
 *
 * Awards full marks when entropy exceeds 50 bits.
 *
 * @param {{ bits: number }} bruteForceEntropy
 * @returns {{ points: number, max: number, detail: string }}
 */
function scoreEntropy(bruteForceEntropy) {
  const bits = bruteForceEntropy?.bits ?? 0;

  if (bits > 50) {
    return {
      points: 10,
      max: 10,
      detail: `Entropy ${bits.toFixed(1)} bits (>50): bonus awarded`,
    };
  }

  return {
    points: 0,
    max: 10,
    detail: `Entropy ${bits.toFixed(1)} bits (≤50): no bonus`,
  };
}

// ─── Label resolution ────────────────────────────────────────────────────────

/**
 * Map a numeric score to its human-readable label and emoji.
 *
 * @param {number} score - Composite score (0-100).
 * @returns {{ label: string, emoji: string }}
 */
function resolveLabel(score) {
  for (const tier of STRENGTH_TIERS) {
    if (score <= tier.ceiling) {
      return { label: tier.label, emoji: tier.emoji };
    }
  }
  // Fallback (should never be reached for valid 0-100 scores)
  return { label: 'Very Strong', emoji: '🔒' };
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Calculate a composite password strength score.
 *
 * @param {string} password - The plaintext password to evaluate.
 * @param {Object} analysisResults - Pre-computed analysis data.
 * @param {{ count: number, poolSize: number, lowercase: boolean, uppercase: boolean, digits: boolean, symbols: boolean }} analysisResults.charsets
 *   Character-set breakdown produced by the analyser.
 * @param {Array<{ severity?: string }>} analysisResults.patterns
 *   Array of detected pattern objects (each should carry a `severity` field).
 * @param {{ found: boolean, matches: Array }} analysisResults.dictionary
 *   Dictionary check results.
 * @param {{ bits: number }} analysisResults.bruteForceEntropy
 *   Brute-force entropy estimate.
 *
 * @returns {{
 *   score: number,
 *   label: string,
 *   emoji: string,
 *   breakdown: {
 *     length:     { points: number, max: 35, detail: string },
 *     charset:    { points: number, max: 20, detail: string },
 *     dictionary: { points: number, max: 20, detail: string },
 *     patterns:   { points: number, max: 15, detail: string },
 *     entropy:    { points: number, max: 10, detail: string }
 *   }
 * }}
 */
export function calculateScore(password, analysisResults) {
  const { charsets, patterns, dictionary, bruteForceEntropy } = analysisResults;

  // Build the per-category breakdown
  const breakdown = {
    length:     scoreLength(password.length),
    charset:    scoreCharset(charsets),
    dictionary: scoreDictionary(dictionary),
    patterns:   scorePatterns(patterns),
    entropy:    scoreEntropy(bruteForceEntropy),
  };

  // Sum all category points and clamp to [0, 100]
  const raw =
    breakdown.length.points +
    breakdown.charset.points +
    breakdown.dictionary.points +
    breakdown.patterns.points +
    breakdown.entropy.points;

  const score = Math.max(0, Math.min(100, raw));
  const { label, emoji } = resolveLabel(score);

  return { score, label, emoji, breakdown };
}
