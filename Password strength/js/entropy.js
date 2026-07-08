/**
 * @module entropy
 * Password entropy calculation utilities.
 *
 * Provides three core functions for analysing the randomness / strength of a
 * password from an information-theory perspective:
 *   - detectCharsets        – identify which character classes are present
 *   - calculateBruteForceEntropy – classic brute-force search-space estimate
 *   - calculateShannonEntropy    – per-character Shannon entropy
 */

// ─── Character-class definitions ────────────────────────────────────────────

/** @constant {RegExp} Matches any lowercase ASCII letter. */
const RE_LOWER = /[a-z]/;

/** @constant {RegExp} Matches any uppercase ASCII letter. */
const RE_UPPER = /[A-Z]/;

/** @constant {RegExp} Matches any ASCII digit. */
const RE_DIGIT = /[0-9]/;

/**
 * Matches any printable ASCII character that is NOT a letter or digit.
 * This covers the 32 common symbol characters on a US keyboard.
 * @constant {RegExp}
 */
const RE_SYMBOL = /[^a-zA-Z0-9]/;

/** Size of each character pool when it is present. */
const POOL_SIZES = Object.freeze({
  lowercase: 26,
  uppercase: 26,
  digits: 10,
  symbols: 32,
});

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Detect which character sets (lowercase, uppercase, digits, symbols) are
 * present in the given password and compute the resulting pool size.
 *
 * @param {string} password - The password to analyse.
 * @returns {{
 *   lowercase: boolean,
 *   uppercase: boolean,
 *   digits:    boolean,
 *   symbols:   boolean,
 *   poolSize:  number,
 *   count:     number
 * }} An object describing the detected character classes.
 *
 * @example
 * detectCharsets('Hello1!');
 * // => { lowercase: true, uppercase: true, digits: true, symbols: true,
 * //      poolSize: 94, count: 4 }
 */
export function detectCharsets(password) {
  if (typeof password !== 'string' || password.length === 0) {
    return {
      lowercase: false,
      uppercase: false,
      digits: false,
      symbols: false,
      poolSize: 0,
      count: 0,
    };
  }

  const lowercase = RE_LOWER.test(password);
  const uppercase = RE_UPPER.test(password);
  const digits = RE_DIGIT.test(password);
  const symbols = RE_SYMBOL.test(password);

  let poolSize = 0;
  if (lowercase) poolSize += POOL_SIZES.lowercase;
  if (uppercase) poolSize += POOL_SIZES.uppercase;
  if (digits) poolSize += POOL_SIZES.digits;
  if (symbols) poolSize += POOL_SIZES.symbols;

  const count = [lowercase, uppercase, digits, symbols].filter(Boolean).length;

  return { lowercase, uppercase, digits, symbols, poolSize, count };
}

/**
 * Calculate the brute-force entropy of a password.
 *
 * Entropy (in bits) is defined as:
 *   E = log₂(poolSize ^ length)
 *     = length × log₂(poolSize)
 *
 * The search space is returned as a human-readable string in scientific
 * notation (e.g. "2.8 × 10^14").
 *
 * @param {string} password - The password to analyse.
 * @returns {{
 *   bits:        number,
 *   poolSize:    number,
 *   searchSpace: string
 * }} Brute-force entropy metrics.
 *
 * @example
 * calculateBruteForceEntropy('abc123');
 * // => { bits: 35.73…, poolSize: 36, searchSpace: '2.2 × 10^9' }
 */
export function calculateBruteForceEntropy(password) {
  if (typeof password !== 'string' || password.length === 0) {
    return { bits: 0, poolSize: 0, searchSpace: '0' };
  }

  const { poolSize } = detectCharsets(password);
  const length = password.length;

  // bits = log2(poolSize ^ length) = length * log2(poolSize)
  const bits = length * Math.log2(poolSize);

  // Compute the raw search space (poolSize ^ length) and format it.
  const searchSpace = formatSearchSpace(poolSize, length);

  return { bits, poolSize, searchSpace };
}

/**
 * Calculate the Shannon entropy of a password.
 *
 * Shannon entropy measures the average information content per character
 * based on the actual frequency distribution of characters in the string:
 *
 *   H = −Σ p(x) × log₂(p(x))
 *
 * where p(x) = frequency(x) / length for each unique character x.
 *
 * The returned `bits` value is the *total* Shannon entropy (H × length),
 * while `bitsPerChar` is H itself.
 *
 * @param {string} password - The password to analyse.
 * @returns {{
 *   bits:        number,
 *   bitsPerChar: number,
 *   uniqueChars: number
 * }} Shannon entropy metrics.
 *
 * @example
 * calculateShannonEntropy('aab');
 * // => { bits: 2.75…, bitsPerChar: 0.918…, uniqueChars: 2 }
 */
export function calculateShannonEntropy(password) {
  if (typeof password !== 'string' || password.length === 0) {
    return { bits: 0, bitsPerChar: 0, uniqueChars: 0 };
  }

  const length = password.length;

  // Build frequency map
  /** @type {Map<string, number>} */
  const freq = new Map();
  for (const ch of password) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }

  const uniqueChars = freq.size;

  // H = -Σ p(x) * log2(p(x))
  let bitsPerChar = 0;
  for (const count of freq.values()) {
    const p = count / length;
    bitsPerChar -= p * Math.log2(p);
  }

  const bits = bitsPerChar * length;

  return { bits, bitsPerChar, uniqueChars };
}

// ─── Internal helpers ───────────────────────────────────────────────────────

/**
 * Format a search-space value (base ^ exponent) into human-readable
 * scientific notation, e.g. "2.8 × 10^14".
 *
 * Uses logarithms to avoid BigInt or arbitrary-precision arithmetic while
 * still producing an accurate mantissa and exponent.
 *
 * @param {number} base     - The character-pool size.
 * @param {number} exponent - The password length.
 * @returns {string} Formatted search-space string.
 */
function formatSearchSpace(base, exponent) {
  if (base === 0 || exponent === 0) return '0';

  // log10(base ^ exponent) = exponent * log10(base)
  const log10Value = exponent * Math.log10(base);
  const powerOf10 = Math.floor(log10Value);
  const mantissa = Math.pow(10, log10Value - powerOf10);

  // For small values (< 10 000) just show the plain number.
  if (powerOf10 < 4) {
    return Math.round(Math.pow(base, exponent)).toString();
  }

  // Round mantissa to one decimal place.
  const roundedMantissa = Math.round(mantissa * 10) / 10;

  return `${roundedMantissa} × 10^${powerOf10}`;
}
