/**
 * @module patterns
 * @description ES6 module for password pattern detection.
 * Detects keyboard walks, repeated characters, sequential characters,
 * leet-speak substitutions, common suffixes/prefixes, date patterns,
 * and capitalization patterns.
 *
 * All functions are pure — no side effects, no external state mutation.
 */

// ─── Keyboard Layout Definitions ────────────────────────────────────────────

/** @type {string[]} Keyboard rows used for horizontal walk detection */
const KEYBOARD_ROWS = [
  '1234567890',
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm',
];

/** @type {string[]} Keyboard vertical columns (top to bottom) */
const KEYBOARD_COLUMNS = [
  '1qaz', '2wsx', '3edc', '4rfv', '5tgb',
  '6yhn', '7ujm', '8ik', '9ol', '0p',
];

// ─── Leet-speak Mapping ─────────────────────────────────────────────────────

/**
 * Maps leet-speak characters to their plain-text equivalents.
 * Characters that map to multiple letters (e.g. '1' → 'i' or 'l') use
 * the most common substitution first.
 * @type {Record<string, string>}
 */
const LEET_MAP = {
  '@': 'a',
  '4': 'a',
  '3': 'e',
  '0': 'o',
  '1': 'i', // also 'l', handled via secondary pass
  '$': 's',
  '5': 's',
  '7': 't',
  '+': 't',
  '!': 'i',
  '#': 'h',
  '8': 'b',
};

/**
 * Secondary leet mapping for characters with alternate decodings.
 * @type {Record<string, string>}
 */
const LEET_MAP_ALT = {
  '1': 'l',
};

// ─── Common Affixes ─────────────────────────────────────────────────────────

/** @type {string[]} Common suffixes and prefixes that weaken passwords */
const COMMON_AFFIXES = [
  '12345', '1234', '123', '111', '000', '321',
  '@1234', '@123', '@1',
  '#1',
  '!!', '!',
  '01', '007',
  // Years 2020–2026
  '2020', '2021', '2022', '2023', '2024', '2025', '2026',
];

// ─── Helper Utilities ───────────────────────────────────────────────────────

/**
 * Reverses a string.
 * @param {string} str
 * @returns {string}
 */
function reverse(str) {
  return str.split('').reverse().join('');
}

/**
 * Extracts all substrings of a given minimum length from a source string.
 * @param {string} source - The string to extract substrings from.
 * @param {number} minLen - Minimum substring length.
 * @returns {string[]} Array of substrings, longest first.
 */
function getSubstrings(source, minLen) {
  const results = [];
  for (let len = source.length; len >= minLen; len--) {
    for (let start = 0; start <= source.length - len; start++) {
      results.push(source.substring(start, start + len));
    }
  }
  return results;
}

// ─── Pattern Detectors ──────────────────────────────────────────────────────

/**
 * Detects keyboard walk patterns (horizontal rows, vertical columns,
 * and their reversed forms).
 *
 * @param {string} password - The password to analyse.
 * @returns {Array<{type: string, description: string, matched: string, severity: 'critical'|'high'}>}
 */
function detectKeyboardWalks(password) {
  if (!password || password.length < 3) return [];

  const lower = password.toLowerCase();
  const patterns = [];
  const alreadyMatched = new Set();

  /**
   * Checks whether any substring of `source` (min length 3) appears in `lower`
   * and records it as a keyboard walk pattern.
   * @param {string} source - A keyboard row/column string.
   * @param {string} direction - Human-readable direction label.
   */
  function checkSource(source, direction) {
    const substrings = getSubstrings(source, 3);
    for (const sub of substrings) {
      const idx = lower.indexOf(sub);
      if (idx !== -1) {
        const matchKey = `${idx}:${sub}`;
        if (alreadyMatched.has(matchKey)) continue;

        // Skip if this match is fully contained within an already-recorded match
        let dominated = false;
        for (const existing of alreadyMatched) {
          const [eIdx, eSub] = existing.split(':');
          const eStart = parseInt(eIdx, 10);
          const eEnd = eStart + eSub.length;
          if (idx >= eStart && idx + sub.length <= eEnd) {
            dominated = true;
            break;
          }
        }
        if (dominated) continue;

        alreadyMatched.add(matchKey);
        const severity = sub.length >= 5 ? 'critical' : 'high';
        patterns.push({
          type: 'keyboard_walk',
          description: `Keyboard walk detected (${direction}): "${sub}"`,
          matched: password.substring(idx, idx + sub.length),
          severity,
        });
      }
    }
  }

  // Horizontal walks (forward and reversed)
  for (const row of KEYBOARD_ROWS) {
    checkSource(row, 'horizontal');
    checkSource(reverse(row), 'horizontal reversed');
  }

  // Vertical column walks (forward and reversed)
  for (const col of KEYBOARD_COLUMNS) {
    checkSource(col, 'vertical');
    checkSource(reverse(col), 'vertical reversed');
  }

  return patterns;
}

/**
 * Detects repeated character patterns:
 * - Single character repeated 3+ times (e.g. "aaa", "111")
 * - Short pattern repeated 2+ times (e.g. "abab", "123123")
 *
 * @param {string} password - The password to analyse.
 * @returns {Array<{type: string, description: string, matched: string, severity: 'high'}>}
 */
function detectRepeatedChars(password) {
  if (!password) return [];

  const patterns = [];

  // Single character repeats: 3 or more of the same character
  const singleRepeatRegex = /(.)\1{2,}/g;
  let match;
  while ((match = singleRepeatRegex.exec(password)) !== null) {
    patterns.push({
      type: 'repeated_chars',
      description: `Single character "${match[1]}" repeated ${match[0].length} times`,
      matched: match[0],
      severity: 'high',
    });
  }

  // Pattern repeats: a 2–4 character group repeated 2+ times consecutively
  const patternRepeatRegex = /(.{2,4})\1{1,}/g;
  while ((match = patternRepeatRegex.exec(password)) !== null) {
    // Avoid reporting if already fully covered by single-char repeat
    const isSingleCharRepeat = match[0].split('').every(c => c === match[0][0]);
    if (isSingleCharRepeat) continue;

    patterns.push({
      type: 'repeated_chars',
      description: `Repeating pattern "${match[1]}" found (${Math.floor(match[0].length / match[1].length)} repetitions)`,
      matched: match[0],
      severity: 'high',
    });
  }

  return patterns;
}

/**
 * Detects ascending or descending sequential characters (letters or digits)
 * of length 3 or more.
 *
 * @param {string} password - The password to analyse.
 * @returns {Array<{type: string, description: string, matched: string, severity: 'high'|'medium'}>}
 */
function detectSequentialChars(password) {
  if (!password || password.length < 3) return [];

  const patterns = [];
  const lower = password.toLowerCase();

  /**
   * Scans for runs of consecutive char-code increments of `step`.
   * @param {number} step - +1 for ascending, -1 for descending.
   * @param {string} direction - Label for the description.
   */
  function findRuns(step, direction) {
    let runStart = 0;
    let runLength = 1;

    for (let i = 1; i < lower.length; i++) {
      const prev = lower.charCodeAt(i - 1);
      const curr = lower.charCodeAt(i);
      const prevIsDigit = lower[i - 1] >= '0' && lower[i - 1] <= '9';
      const currIsDigit = lower[i] >= '0' && lower[i] <= '9';
      const prevIsLetter = lower[i - 1] >= 'a' && lower[i - 1] <= 'z';
      const currIsLetter = lower[i] >= 'a' && lower[i] <= 'z';

      // Only count sequential within the same character class
      const sameClass = (prevIsDigit && currIsDigit) || (prevIsLetter && currIsLetter);

      if (sameClass && curr - prev === step) {
        runLength++;
      } else {
        if (runLength >= 3) {
          const matched = password.substring(runStart, runStart + runLength);
          const severity = runLength >= 4 ? 'high' : 'medium';
          patterns.push({
            type: 'sequential',
            description: `${direction} sequential characters: "${matched}"`,
            matched,
            severity,
          });
        }
        runStart = i;
        runLength = 1;
      }
    }

    // Flush trailing run
    if (runLength >= 3) {
      const matched = password.substring(runStart, runStart + runLength);
      const severity = runLength >= 4 ? 'high' : 'medium';
      patterns.push({
        type: 'sequential',
        description: `${direction} sequential characters: "${matched}"`,
        matched,
        severity,
      });
    }
  }

  findRuns(1, 'Ascending');
  findRuns(-1, 'Descending');

  return patterns;
}

/**
 * Detects leet-speak substitutions in the password. If the decoded version
 * is 4+ characters and mostly alphabetic, it is flagged.
 *
 * @param {string} password - The password to analyse.
 * @returns {Array<{type: string, description: string, matched: string, decoded: string, severity: 'medium'}>}
 */
function detectLeetSpeak(password) {
  if (!password || password.length < 4) return [];

  const patterns = [];

  /**
   * Decodes a string using the given leet-speak mapping.
   * @param {string} str
   * @param {Record<string, string>} map
   * @returns {string}
   */
  function decode(str, map) {
    return str
      .split('')
      .map(ch => map[ch] || ch)
      .join('');
  }

  // Try primary mapping
  const decoded = decode(password, LEET_MAP);

  // Check if the decoded result is meaningfully different and looks word-like
  if (decoded !== password && decoded.length >= 4) {
    const letterCount = (decoded.match(/[a-zA-Z]/g) || []).length;
    const letterRatio = letterCount / decoded.length;

    if (letterRatio >= 0.6) {
      patterns.push({
        type: 'leet_speak',
        description: `Possible leet-speak detected: "${password}" decodes to "${decoded}"`,
        matched: password,
        decoded,
        severity: 'medium',
      });
    }
  }

  // Try alternate mapping (e.g. '1' → 'l' instead of 'i')
  const mergedAlt = { ...LEET_MAP, ...LEET_MAP_ALT };
  const decodedAlt = decode(password, mergedAlt);

  if (
    decodedAlt !== password &&
    decodedAlt !== decoded && // only report if different from primary
    decodedAlt.length >= 4
  ) {
    const letterCount = (decodedAlt.match(/[a-zA-Z]/g) || []).length;
    const letterRatio = letterCount / decodedAlt.length;

    if (letterRatio >= 0.6) {
      patterns.push({
        type: 'leet_speak',
        description: `Possible leet-speak detected (alt): "${password}" decodes to "${decodedAlt}"`,
        matched: password,
        decoded: decodedAlt,
        severity: 'medium',
      });
    }
  }

  return patterns;
}

/**
 * Detects common password suffixes and prefixes that are frequently
 * appended or prepended by users to meet complexity requirements.
 *
 * @param {string} password - The password to analyse.
 * @returns {Array<{type: string, description: string, matched: string, severity: 'high'}>}
 */
function detectCommonAffixes(password) {
  if (!password) return [];

  const patterns = [];
  const alreadyFlagged = new Set();

  // Sort affixes by descending length so longer matches take priority
  const sorted = [...COMMON_AFFIXES].sort((a, b) => b.length - a.length);

  for (const affix of sorted) {
    // Check suffix
    if (password.endsWith(affix)) {
      const key = `suffix:${affix}`;
      // Avoid flagging if a longer affix already covers it
      if (!alreadyFlagged.has(key)) {
        let dominated = false;
        for (const existing of alreadyFlagged) {
          if (existing.startsWith('suffix:')) {
            const existingAffix = existing.substring(7);
            if (existingAffix.endsWith(affix) && existingAffix.length > affix.length) {
              dominated = true;
              break;
            }
          }
        }
        if (!dominated) {
          alreadyFlagged.add(key);
          patterns.push({
            type: 'common_affix',
            description: `Common suffix detected: "${affix}"`,
            matched: affix,
            severity: 'high',
          });
        }
      }
    }

    // Check prefix
    if (password.startsWith(affix)) {
      const key = `prefix:${affix}`;
      if (!alreadyFlagged.has(key)) {
        let dominated = false;
        for (const existing of alreadyFlagged) {
          if (existing.startsWith('prefix:')) {
            const existingAffix = existing.substring(7);
            if (existingAffix.startsWith(affix) && existingAffix.length > affix.length) {
              dominated = true;
              break;
            }
          }
        }
        if (!dominated) {
          alreadyFlagged.add(key);
          patterns.push({
            type: 'common_affix',
            description: `Common prefix detected: "${affix}"`,
            matched: affix,
            severity: 'high',
          });
        }
      }
    }
  }

  return patterns;
}

/**
 * Detects date-like patterns in the password:
 * - ddmmyyyy / mmddyyyy (8-digit dates)
 * - Birth years in the range 1950–2026
 * - dd/mm or mm-dd with separators
 *
 * @param {string} password - The password to analyse.
 * @returns {Array<{type: string, description: string, matched: string, severity: 'high'}>}
 */
function detectDatePatterns(password) {
  if (!password) return [];

  const patterns = [];
  const flagged = new Set();

  // ddmmyyyy or mmddyyyy (8 contiguous digits forming a plausible date)
  const fullDateRegex = /(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])(19|20)\d{2}/g;
  let match;
  while ((match = fullDateRegex.exec(password)) !== null) {
    const key = `full:${match.index}:${match[0]}`;
    if (!flagged.has(key)) {
      flagged.add(key);
      patterns.push({
        type: 'date_pattern',
        description: `Date-like pattern (dd/mm/yyyy or mm/dd/yyyy): "${match[0]}"`,
        matched: match[0],
        severity: 'high',
      });
    }
  }

  // Birth years (1950–2026)
  const yearRegex = /(19[5-9]\d|200\d|201\d|202[0-6])/g;
  while ((match = yearRegex.exec(password)) !== null) {
    // Skip if this year was already part of a full-date match
    let coveredByFull = false;
    for (const key of flagged) {
      if (key.startsWith('full:')) {
        const parts = key.split(':');
        const fStart = parseInt(parts[1], 10);
        const fLen = parts[2].length;
        if (match.index >= fStart && match.index + match[0].length <= fStart + fLen) {
          coveredByFull = true;
          break;
        }
      }
    }
    if (!coveredByFull) {
      patterns.push({
        type: 'date_pattern',
        description: `Possible birth year detected: "${match[0]}"`,
        matched: match[0],
        severity: 'high',
      });
    }
  }

  // dd/mm or mm-dd with separators (/ - .)
  const separatorDateRegex = /(0[1-9]|[12]\d|3[01])[/\-.](0[1-9]|1[0-2])/g;
  while ((match = separatorDateRegex.exec(password)) !== null) {
    patterns.push({
      type: 'date_pattern',
      description: `Date fragment with separator: "${match[0]}"`,
      matched: match[0],
      severity: 'high',
    });
  }

  return patterns;
}

/**
 * Detects common capitalisation patterns that provide minimal entropy:
 * - Only the first character is uppercase (e.g. "Password")
 * - Only the last character is uppercase (e.g. "passworD")
 * - Entire password is uppercase (e.g. "PASSWORD")
 *
 * @param {string} password - The password to analyse.
 * @returns {Array<{type: string, description: string, matched: string, severity: 'low'}>}
 */
function detectCapitalizationPatterns(password) {
  if (!password || password.length < 2) return [];

  const patterns = [];

  // Only first character uppercase, rest lowercase
  if (/^[A-Z][a-z]+$/.test(password)) {
    patterns.push({
      type: 'cap_pattern',
      description: 'Only the first character is capitalised — a very common pattern',
      matched: password,
      severity: 'low',
    });
  }

  // Only last character uppercase, rest lowercase
  if (/^[a-z]+[A-Z]$/.test(password)) {
    patterns.push({
      type: 'cap_pattern',
      description: 'Only the last character is capitalised — a predictable pattern',
      matched: password,
      severity: 'low',
    });
  }

  // Entire password is uppercase (at least 2 letters)
  if (/^[A-Z]{2,}$/.test(password)) {
    patterns.push({
      type: 'cap_pattern',
      description: 'Entire password is uppercase — adds no real complexity',
      matched: password,
      severity: 'low',
    });
  }

  return patterns;
}

// ─── Main Entry Point ───────────────────────────────────────────────────────

/**
 * Runs all pattern detectors against the given password and returns a
 * combined, deduplicated array of pattern objects.
 *
 * @param {string} password - The password string to analyse.
 * @returns {Array<{
 *   type: string,
 *   description: string,
 *   matched: string,
 *   severity: 'critical'|'high'|'medium'|'low',
 *   decoded?: string
 * }>} An array of detected pattern objects. Empty array if no patterns found
 *       or if the password is empty/falsy.
 *
 * @example
 * const results = detectAllPatterns('qwerty123!');
 * // [
 * //   { type: 'keyboard_walk', description: '...', matched: 'qwerty', severity: 'critical' },
 * //   { type: 'sequential', description: '...', matched: '123', severity: 'medium' },
 * //   { type: 'common_affix', description: '...', matched: '!', severity: 'high' },
 * //   ...
 * // ]
 */
export function detectAllPatterns(password) {
  if (!password || typeof password !== 'string') {
    return [];
  }

  return [
    ...detectKeyboardWalks(password),
    ...detectRepeatedChars(password),
    ...detectSequentialChars(password),
    ...detectLeetSpeak(password),
    ...detectCommonAffixes(password),
    ...detectDatePatterns(password),
    ...detectCapitalizationPatterns(password),
  ];
}
