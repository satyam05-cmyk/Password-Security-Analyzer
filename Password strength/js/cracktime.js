/**
 * @module cracktime
 * ES6 module for estimating password crack times across multiple attack scenarios.
 * Uses logarithmic math to safely handle very large search spaces without overflow.
 */

/**
 * Convert a duration in seconds to a human-readable string.
 * Uses the largest meaningful unit and rounds to 1 decimal place where relevant.
 *
 * @param {number} seconds - The duration in seconds to format.
 * @returns {string} A human-readable time string (e.g. "3.2 hours", "Instant").
 */
export function formatTime(seconds) {
  if (seconds < 0.001) {
    return 'Instant';
  }
  if (seconds < 1) {
    return 'Less than a second';
  }
  if (seconds < 60) {
    const val = Math.round(seconds * 10) / 10;
    return `${val} second${val !== 1 ? 's' : ''}`;
  }
  if (seconds < 3600) {
    const val = Math.round((seconds / 60) * 10) / 10;
    return `${val} minute${val !== 1 ? 's' : ''}`;
  }
  if (seconds < 86400) {
    const val = Math.round((seconds / 3600) * 10) / 10;
    return `${val} hour${val !== 1 ? 's' : ''}`;
  }

  const YEAR = 31536000; // 365 days in seconds

  if (seconds < YEAR) {
    const days = seconds / 86400;
    if (days >= 60) {
      // Express as months (approximate: 30.44 days/month)
      const months = Math.round((days / 30.44) * 10) / 10;
      return `${months} month${months !== 1 ? 's' : ''}`;
    }
    const val = Math.round(days * 10) / 10;
    return `${val} day${val !== 1 ? 's' : ''}`;
  }
  if (seconds < YEAR * 100) {
    const val = Math.round((seconds / YEAR) * 10) / 10;
    return `${val} year${val !== 1 ? 's' : ''}`;
  }
  if (seconds < YEAR * 1000) {
    const val = Math.round((seconds / (YEAR * 100)) * 10) / 10;
    return `${val} centur${val !== 1 ? 'ies' : 'y'}`;
  }
  if (seconds < YEAR * 1e6) {
    const val = Math.round((seconds / (YEAR * 1000)) * 10) / 10;
    return `${val} millenni${val !== 1 ? 'a' : 'um'}`;
  }

  // Beyond a million years — check if it's truly astronomical
  if (seconds < YEAR * 1e15) {
    return 'Millions of years';
  }

  return 'Heat death of universe ♾️';
}

/**
 * Estimate how long it would take to crack a password under various attack scenarios.
 *
 * Uses logarithms to compute search-space metrics safely:
 *   log10(seconds) = log10(poolSize) * length − log10(2) − log10(speed)
 *
 * If the result exceeds 10^20 seconds the numeric value is set to Infinity and
 * the display string is derived directly from the logarithmic magnitude.
 *
 * @param {string} password - The password to evaluate.
 * @param {{ poolSize: number }} charsetInfo - Charset information from entropy.js.
 *   Must contain at least `poolSize` (the number of possible characters).
 * @returns {{
 *   onlineThrottled:   { speed: number, speedLabel: string, seconds: number, display: string },
 *   onlineUnthrottled: { speed: number, speedLabel: string, seconds: number, display: string },
 *   offlineBcrypt:     { speed: number, speedLabel: string, seconds: number, display: string },
 *   offlineMD5:        { speed: number, speedLabel: string, seconds: number, display: string }
 * }} An object with crack-time estimates for four attack scenarios.
 */
export function estimateCrackTimes(password, charsetInfo) {
  const length = password.length;
  const poolSize = charsetInfo.poolSize;

  // Define the four attack scenarios
  const scenarios = {
    onlineThrottled:   { speed: 100,   speedLabel: '100/sec' },
    onlineUnthrottled: { speed: 10000, speedLabel: '10K/sec' },
    offlineBcrypt:     { speed: 10000, speedLabel: '10K/sec' },
    offlineMD5:        { speed: 1e10,  speedLabel: '10B/sec' },
  };

  // Handle edge case: empty password or zero pool
  if (length === 0 || poolSize <= 0) {
    const result = {};
    for (const [key, scenario] of Object.entries(scenarios)) {
      result[key] = {
        speed: scenario.speed,
        speedLabel: scenario.speedLabel,
        seconds: 0,
        display: 'Instant',
      };
    }
    return result;
  }

  // Use logarithmic math to avoid overflow with large search spaces.
  // Search space = poolSize ^ length
  // Average attempts = searchSpace / 2
  // Seconds = averageAttempts / speed
  //
  // In log10 space:
  //   log10(seconds) = log10(poolSize) * length − log10(2) − log10(speed)
  const log10Pool = Math.log10(poolSize);
  const log10Two = Math.log10(2);

  const result = {};

  for (const [key, scenario] of Object.entries(scenarios)) {
    const log10Speed = Math.log10(scenario.speed);
    const log10Seconds = log10Pool * length - log10Two - log10Speed;

    let seconds;
    let display;

    if (log10Seconds > 20) {
      // Number is too large for standard floating-point precision;
      // derive the display string from the logarithmic magnitude instead.
      seconds = Infinity;
      display = formatTimeFromLog10(log10Seconds);
    } else if (log10Seconds < -3) {
      // Essentially instant
      seconds = 0;
      display = 'Instant';
    } else {
      seconds = Math.pow(10, log10Seconds);
      display = formatTime(seconds);
    }

    result[key] = {
      speed: scenario.speed,
      speedLabel: scenario.speedLabel,
      seconds,
      display,
    };
  }

  return result;
}

/**
 * Convert a log10(seconds) value directly to a human-readable time string.
 * Used when the raw number of seconds is too large for standard floating-point.
 *
 * @param {number} log10Secs - The base-10 logarithm of the duration in seconds.
 * @returns {string} A human-readable time string.
 * @private
 */
function formatTimeFromLog10(log10Secs) {
  const YEAR = 31536000;
  const log10Year = Math.log10(YEAR); // ≈ 7.499

  // log10 of the number of years
  const log10Years = log10Secs - log10Year;

  if (log10Years < 0) {
    // Less than a year — fall back to converting (should rarely be hit here)
    return formatTime(Math.pow(10, log10Secs));
  }

  if (log10Years < 2) {
    // Up to ~100 years
    const years = Math.pow(10, log10Years);
    const val = Math.round(years * 10) / 10;
    return `${val} year${val !== 1 ? 's' : ''}`;
  }

  if (log10Years < 3) {
    // Up to ~1000 years → centuries
    const centuries = Math.pow(10, log10Years - 2);
    const val = Math.round(centuries * 10) / 10;
    return `${val} centur${val !== 1 ? 'ies' : 'y'}`;
  }

  if (log10Years < 6) {
    // Up to ~1 million years → millennia
    const millennia = Math.pow(10, log10Years - 3);
    const val = Math.round(millennia * 10) / 10;
    return `${val} millenni${val !== 1 ? 'a' : 'um'}`;
  }

  if (log10Years < 15) {
    return 'Millions of years';
  }

  return 'Heat death of universe ♾️';
}
