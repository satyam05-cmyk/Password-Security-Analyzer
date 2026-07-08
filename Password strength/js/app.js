/**
 * @module app
 * @description Main controller for Password Security Analyst.
 * Orchestrates all analysis modules, handles UI events, and renders results
 * with staggered animations.
 */

import { detectCharsets, calculateBruteForceEntropy, calculateShannonEntropy } from './entropy.js';
import { detectAllPatterns } from './patterns.js';
import { checkDictionary } from './dictionary.js';
import { estimateCrackTimes } from './cracktime.js';
import { calculateScore } from './scorer.js';
import { generateSuggestions, generatePassphrase } from './suggestions.js';

// ─── DOM References ─────────────────────────────────────────────────────────

const passwordInput = document.getElementById('password-input');
const toggleVisibility = document.getElementById('toggle-visibility');
const charCountEl = document.getElementById('char-count');
const miniStrengthFill = document.getElementById('mini-strength-fill');
const analyzeBtn = document.getElementById('analyze-btn');
const resultsSection = document.getElementById('results');

// Charset pills
const pillLower = document.getElementById('pill-lower');
const pillUpper = document.getElementById('pill-upper');
const pillDigit = document.getElementById('pill-digit');
const pillSymbol = document.getElementById('pill-symbol');

// Score card
const scoreRingFill = document.getElementById('score-ring-fill');
const scoreNumber = document.getElementById('score-number');
const scoreLabel = document.getElementById('score-label');
const scorePassword = document.getElementById('score-password');

// Breakdown
const breakdownTbody = document.getElementById('breakdown-tbody');

// Entropy
const bruteEntropyValue = document.getElementById('brute-entropy-value');
const shannonEntropyValue = document.getElementById('shannon-entropy-value');
const uniqueCharsValue = document.getElementById('unique-chars-value');
const searchSpaceValue = document.getElementById('search-space-value');
const entropyBarFill = document.getElementById('entropy-bar-fill');

// Charset grid
const csLowercase = document.getElementById('cs-lowercase');
const csUppercase = document.getElementById('cs-uppercase');
const csDigits = document.getElementById('cs-digits');
const csSymbols = document.getElementById('cs-symbols');

// Crack time
const ctOnlineThrottled = document.getElementById('ct-online-throttled');
const ctOnlineUnthrottled = document.getElementById('ct-online-unthrottled');
const ctOfflineBcrypt = document.getElementById('ct-offline-bcrypt');
const ctOfflineMD5 = document.getElementById('ct-offline-md5');

// Weaknesses
const weaknessList = document.getElementById('weakness-list');

// Suggestions
const suggestionList = document.getElementById('suggestion-list');
const passphraseValue = document.getElementById('passphrase-value');
const passphraseEntropy = document.getElementById('passphrase-entropy');
const copyPassphrase = document.getElementById('copy-passphrase');
const copyFeedback = document.getElementById('copy-feedback');

// ─── Utilities ──────────────────────────────────────────────────────────────

/**
 * Mask a password for display: show first 2 chars + asterisks.
 * @param {string} pw
 * @returns {string}
 */
function maskPassword(pw) {
  if (pw.length <= 2) return '*'.repeat(pw.length);
  return pw.substring(0, 2) + '*'.repeat(pw.length - 2);
}

/**
 * Get CSS class for crack time color-coding.
 * @param {number} seconds
 * @returns {string}
 */
function crackTimeClass(seconds) {
  if (seconds === 0 || seconds < 1) return 'instant';
  if (seconds < 3600) return 'fast';
  if (seconds < 86400 * 30) return 'medium';
  if (seconds < 31536000 * 100) return 'slow';
  return 'very-slow';
}

/**
 * Get CSS class for score label.
 * @param {string} label
 * @returns {string}
 */
function scoreLabelClass(label) {
  const map = {
    'Very Weak': 'very-weak',
    'Weak': 'weak',
    'Moderate': 'moderate',
    'Strong': 'strong',
    'Very Strong': 'very-strong',
  };
  return map[label] || 'weak';
}

/**
 * Get color variable name from score.
 * @param {number} score
 * @returns {string}
 */
function getScoreColor(score) {
  if (score <= 39) return 'var(--color-danger)';
  if (score <= 59) return 'var(--color-warning)';
  if (score <= 74) return 'var(--color-caution)';
  if (score <= 89) return 'var(--color-success)';
  return 'var(--color-excellent)';
}

/**
 * Animate a number counting up from 0 to target.
 * @param {HTMLElement} el
 * @param {number} target
 * @param {number} duration - ms
 */
function animateNumber(el, target, duration = 1200) {
  const startTime = performance.now();
  const update = (currentTime) => {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    // Ease-out cubic
    const easedProgress = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(easedProgress * target);
    el.textContent = current;
    if (progress < 1) {
      requestAnimationFrame(update);
    }
  };
  requestAnimationFrame(update);
}

/**
 * Compute a quick mini-strength level (0-5) for real-time feedback.
 * @param {string} pw
 * @returns {number}
 */
function quickStrengthLevel(pw) {
  if (!pw) return 0;
  const len = pw.length;
  const cs = detectCharsets(pw);
  let level = 0;
  if (len >= 4) level = 1;
  if (len >= 8 && cs.count >= 2) level = 2;
  if (len >= 10 && cs.count >= 3) level = 3;
  if (len >= 12 && cs.count >= 3) level = 4;
  if (len >= 14 && cs.count >= 4) level = 5;
  return level;
}

/**
 * Map strength level to mini-bar color and width.
 * @param {number} level
 * @returns {{width: string, color: string}}
 */
function miniBarStyle(level) {
  const styles = [
    { width: '0%', color: 'transparent' },
    { width: '20%', color: 'var(--color-danger)' },
    { width: '40%', color: 'var(--color-warning)' },
    { width: '60%', color: 'var(--color-caution)' },
    { width: '80%', color: 'var(--color-success)' },
    { width: '100%', color: 'var(--color-excellent)' },
  ];
  return styles[level] || styles[0];
}

/**
 * Get the educational explanation (what + why + how attacker exploits it)
 * for each weakness type.
 * @param {object} pattern
 * @param {object} dictMatch
 * @returns {string}
 */
function getEducationalExplanation(pattern, dictMatch) {
  if (dictMatch) {
    const typeExplanations = {
      exact: `This is a direct match in known password databases. Credential-stuffing attacks use lists of millions of leaked passwords, and this one is on them.`,
      leet: `Leet-speak substitutions (e.g. '@' for 'a', '3' for 'e') are well-known to cracking tools and are tested automatically during dictionary attacks.`,
      reverse: `Reversing a common word is a standard technique that cracking tools account for. Reversed dictionaries are tested alongside regular ones.`,
      contains: `A common dictionary word was detected as a substring. Attackers routinely test dictionary words combined with short prefixes or suffixes.`,
    };
    return typeExplanations[dictMatch.type] || typeExplanations.exact;
  }

  if (pattern) {
    const typeExplanations = {
      keyboard_walk: `Adjacent keyboard sequences are among the first patterns tested by cracking tools. They dramatically reduce the effective search space.`,
      repeated_chars: `Repeated characters add very little entropy. Cracking tools collapse repetitions, treating "aaa" as equivalent to "a" in their search.`,
      sequential: `Sequential characters (e.g. "123", "abc") are trivially predictable. Cracking software enumerates these patterns early in the attack.`,
      leet_speak: `Leet-speak substitutions (e.g. '0' for 'O') are a well-known technique. Modern cracking tools apply these transformations automatically.`,
      common_affix: `Common suffixes and prefixes (e.g. "123", "!") are tested automatically. Attackers maintain large lists of frequently appended strings.`,
      date_pattern: `Date patterns (birthdays, years) are frequently used in passwords. Attackers systematically enumerate all plausible date combinations.`,
      cap_pattern: `Capitalizing only the first or last letter is the most common capitalization pattern and is always tested first by cracking tools.`,
    };
    return typeExplanations[pattern.type] || `This pattern reduces the effective entropy of the password. Consider replacing this section with random characters.`;
  }

  return '';
}

// ─── Real-time Input Handler ────────────────────────────────────────────────

passwordInput.addEventListener('input', () => {
  const pw = passwordInput.value;
  const len = pw.length;

  // Update character count
  charCountEl.textContent = `${len} character${len !== 1 ? 's' : ''}`;
  charCountEl.classList.toggle('active', len > 0);

  // Update charset pills
  const cs = detectCharsets(pw);
  pillLower.classList.toggle('active', cs.lowercase);
  pillUpper.classList.toggle('active', cs.uppercase);
  pillDigit.classList.toggle('active', cs.digits);
  pillSymbol.classList.toggle('active', cs.symbols);

  // Update mini strength bar
  const level = quickStrengthLevel(pw);
  const style = miniBarStyle(level);
  miniStrengthFill.style.width = style.width;
  miniStrengthFill.style.background = style.color;

  // Update input border color
  passwordInput.className = 'password-input';
  if (len > 0) {
    passwordInput.classList.add(`strength-${level}`);
  }

  // Enable/disable button
  analyzeBtn.disabled = len === 0;
});

// ─── Toggle Visibility ─────────────────────────────────────────────────────

toggleVisibility.addEventListener('click', () => {
  const isPassword = passwordInput.type === 'password';
  passwordInput.type = isPassword ? 'text' : 'password';
  toggleVisibility.textContent = isPassword ? '🙈' : '👁️';
});

// ─── Analyze Handler ────────────────────────────────────────────────────────

function runAnalysis() {
  const password = passwordInput.value;
  if (!password) return;

  // Show loading state
  analyzeBtn.classList.add('loading');
  analyzeBtn.disabled = true;

  // Small delay for loading animation feel
  setTimeout(() => {
    try {
      performAnalysis(password);
    } finally {
      analyzeBtn.classList.remove('loading');
      analyzeBtn.disabled = false;
    }
  }, 300);
}

analyzeBtn.addEventListener('click', runAnalysis);
passwordInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && passwordInput.value) {
    runAnalysis();
  }
});

// ─── Core Analysis ──────────────────────────────────────────────────────────

function performAnalysis(password) {
  // 1. Entropy
  const charsets = detectCharsets(password);
  const bruteForce = calculateBruteForceEntropy(password);
  const shannon = calculateShannonEntropy(password);

  // 2. Pattern detection
  const patterns = detectAllPatterns(password);

  // 3. Dictionary check
  const dictionary = checkDictionary(password);

  // 4. Crack time
  const crackTimes = estimateCrackTimes(password, charsets);

  // 5. Score
  const analysisResults = {
    charsets,
    patterns,
    dictionary,
    bruteForceEntropy: bruteForce,
  };
  const scoreResult = calculateScore(password, analysisResults);

  // 6. Suggestions
  const suggestionsInput = {
    charsets,
    patterns,
    dictionary,
    score: scoreResult,
    bruteForceEntropy: bruteForce,
  };
  const suggestions = generateSuggestions(password, suggestionsInput);
  const passphrase = generatePassphrase();

  // ─── Render Results ─────────────────────────────────────────────────

  renderScoreCard(password, scoreResult);
  renderBreakdown(scoreResult.breakdown);
  renderEntropy(bruteForce, shannon);
  renderCharset(charsets);
  renderCrackTimes(crackTimes);
  renderWeaknesses(patterns, dictionary);
  renderSuggestions(suggestions, passphrase);

  // Show results with animation
  resultsSection.classList.add('visible');

  // Stagger card animations
  const cards = resultsSection.querySelectorAll('.card');
  cards.forEach((card, i) => {
    card.classList.remove('animate-in');
    setTimeout(() => {
      card.classList.add('animate-in');
    }, i * 100);
  });

  // Scroll to results
  setTimeout(() => {
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 200);
}

// ─── Render Functions ───────────────────────────────────────────────────────

function renderScoreCard(password, scoreResult) {
  // Masked password
  scorePassword.textContent = maskPassword(password);

  // Score label
  scoreLabel.textContent = `${scoreResult.emoji} ${scoreResult.label}`;
  scoreLabel.className = `score-label ${scoreLabelClass(scoreResult.label)}`;

  // Animate score number
  animateNumber(scoreNumber, scoreResult.score, 1400);

  // Animate ring
  const circumference = 2 * Math.PI * 80; // r=80
  const offset = circumference - (scoreResult.score / 100) * circumference;
  const color = getScoreColor(scoreResult.score);

  setTimeout(() => {
    scoreRingFill.style.strokeDashoffset = offset;
    scoreRingFill.style.stroke = color;
  }, 100);
}

function renderBreakdown(breakdown) {
  breakdownTbody.innerHTML = '';

  const categories = [
    { key: 'length', icon: '📏', name: 'Length' },
    { key: 'charset', icon: '🔤', name: 'Charset' },
    { key: 'dictionary', icon: '📖', name: 'Dictionary' },
    { key: 'patterns', icon: '🔍', name: 'Patterns' },
    { key: 'entropy', icon: '🎲', name: 'Entropy' },
  ];

  for (const cat of categories) {
    const data = breakdown[cat.key];
    const pct = (data.points / data.max) * 100;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${cat.icon} ${cat.name}</td>
      <td>${data.points}/${data.max}
        <span class="points-bar"><span class="points-bar__fill" style="width: ${pct}%"></span></span>
      </td>
      <td>${data.detail}</td>
    `;
    breakdownTbody.appendChild(tr);
  }
}

function renderEntropy(bruteForce, shannon) {
  bruteEntropyValue.textContent = `${bruteForce.bits.toFixed(1)} bits`;
  shannonEntropyValue.textContent = `${shannon.bits.toFixed(1)} bits (${shannon.bitsPerChar.toFixed(2)}/char)`;
  uniqueCharsValue.textContent = `${shannon.uniqueChars}`;
  searchSpaceValue.textContent = bruteForce.searchSpace;

  // Entropy bar (max at 128 bits)
  const pct = Math.min(100, (bruteForce.bits / 128) * 100);
  setTimeout(() => {
    entropyBarFill.style.width = `${pct}%`;
  }, 200);
}

function renderCharset(charsets) {
  csLowercase.classList.toggle('active', charsets.lowercase);
  csUppercase.classList.toggle('active', charsets.uppercase);
  csDigits.classList.toggle('active', charsets.digits);
  csSymbols.classList.toggle('active', charsets.symbols);
}

function renderCrackTimes(crackTimes) {
  const entries = [
    { el: ctOnlineThrottled, data: crackTimes.onlineThrottled },
    { el: ctOnlineUnthrottled, data: crackTimes.onlineUnthrottled },
    { el: ctOfflineBcrypt, data: crackTimes.offlineBcrypt },
    { el: ctOfflineMD5, data: crackTimes.offlineMD5 },
  ];

  for (const entry of entries) {
    entry.el.textContent = entry.data.display;
    entry.el.className = `stat-value ${crackTimeClass(entry.data.seconds)}`;
  }
}

function renderWeaknesses(patterns, dictionary) {
  weaknessList.innerHTML = '';

  const items = [];

  // Add dictionary weaknesses
  if (dictionary.found) {
    for (const match of dictionary.matches) {
      items.push({
        severity: 'critical',
        type: `Dictionary Match (${match.type})`,
        matched: match.word,
        description: match.category.replace(/_/g, ' '),
        explanation: getEducationalExplanation(null, match),
      });
    }
  }

  // Add pattern weaknesses
  for (const pattern of patterns) {
    items.push({
      severity: pattern.severity,
      type: formatPatternType(pattern.type),
      matched: pattern.matched,
      description: pattern.description,
      explanation: getEducationalExplanation(pattern, null),
    });
  }

  if (items.length === 0) {
    weaknessList.innerHTML = `
      <div class="no-weaknesses">
        <span class="no-weaknesses__icon">🛡️</span>
        No major weaknesses detected! Your password avoids common patterns and dictionary words.
      </div>
    `;
    return;
  }

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    const li = document.createElement('li');
    li.className = `weakness-item ${item.severity}`;
    li.innerHTML = `
      <div class="weakness-item__header">
        <span class="weakness-item__severity ${item.severity}">${item.severity.toUpperCase()}</span>
        <span class="weakness-item__type">${item.type}</span>
        ${item.matched ? `<span class="weakness-item__matched">${escapeHtml(item.matched)}</span>` : ''}
      </div>
      <div class="weakness-item__description">
        ${item.explanation}
      </div>
    `;
    weaknessList.appendChild(li);
  }
}

function renderSuggestions(suggestions, passphrase) {
  suggestionList.innerHTML = '';

  for (const suggestion of suggestions) {
    const li = document.createElement('li');
    li.className = 'suggestion-item';
    // Convert backtick-wrapped text to <code> tags
    const formattedText = suggestion.replace(/`([^`]+)`/g, '<code>$1</code>');
    li.innerHTML = `<div class="suggestion-item__text">${formattedText}</div>`;
    suggestionList.appendChild(li);
  }

  // Passphrase
  passphraseValue.textContent = passphrase.passphrase;
  passphraseEntropy.textContent = `~${passphrase.entropy} bits of entropy · ${passphrase.wordCount} words`;
}

// ─── Helper Formatting Functions ────────────────────────────────────────────

function formatPatternType(type) {
  const names = {
    keyboard_walk: 'Keyboard Walk',
    repeated_chars: 'Repeated Characters',
    sequential: 'Sequential Characters',
    leet_speak: 'Leet-Speak Substitution',
    common_affix: 'Common Suffix/Prefix',
    date_pattern: 'Date Pattern',
    cap_pattern: 'Capitalization Pattern',
  };
  return names[type] || type;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ─── Copy Passphrase ────────────────────────────────────────────────────────

copyPassphrase.addEventListener('click', () => {
  const text = passphraseValue.textContent;
  if (!text || text === '--') return;

  navigator.clipboard.writeText(text).then(() => {
    copyFeedback.classList.add('show');
    setTimeout(() => {
      copyFeedback.classList.remove('show');
    }, 2000);
  }).catch(() => {
    // Fallback for older browsers
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    copyFeedback.classList.add('show');
    setTimeout(() => {
      copyFeedback.classList.remove('show');
    }, 2000);
  });
});

// ─── Focus input on load ────────────────────────────────────────────────────
window.addEventListener('load', () => {
  passwordInput.focus();
});
