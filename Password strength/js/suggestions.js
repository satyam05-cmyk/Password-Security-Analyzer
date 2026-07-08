/**
 * @module suggestions
 * @description ES6 module for generating password improvement suggestions
 * and secure passphrases.
 */

// ─── Curated wordlist (~300 words) across diverse categories ─────────────────
// Categories: animals, foods, colors, actions, objects, nature, adjectives, verbs
// Words are common enough to remember but NOT from typical password dictionaries.
const PASSPHRASE_WORDLIST = [
  // Animals (40)
  'falcon', 'otter', 'badger', 'walrus', 'parrot', 'bison', 'crane', 'gecko',
  'pelican', 'mantis', 'ferret', 'iguana', 'osprey', 'marmot', 'starling',
  'coyote', 'donkey', 'salmon', 'hermit', 'toucan', 'shrimp', 'beetle',
  'cricket', 'lobster', 'panda', 'jackal', 'moose', 'stork', 'heron',
  'buffalo', 'condor', 'alpaca', 'finch', 'wombat', 'lemur', 'newt',
  'viper', 'quail', 'macaw', 'chipmunk',

  // Foods (40)
  'pretzel', 'waffle', 'turnip', 'radish', 'muffin', 'cashew', 'pickle',
  'biscuit', 'ginger', 'celery', 'walnut', 'pastry', 'barley', 'mango',
  'apricot', 'fennel', 'garlic', 'pepper', 'yogurt', 'almond', 'cherry',
  'cumin', 'olive', 'peach', 'plum', 'lemon', 'melon', 'grape',
  'carrot', 'onion', 'bacon', 'toast', 'honey', 'syrup', 'butter',
  'cocoa', 'clove', 'thyme', 'basil', 'nutmeg',

  // Colors & Appearance (25)
  'amber', 'coral', 'ivory', 'scarlet', 'violet', 'indigo', 'bronze',
  'copper', 'silver', 'golden', 'maroon', 'rustic', 'glossy', 'vivid',
  'bright', 'frosty', 'dusty', 'smoky', 'cloudy', 'shiny', 'crisp',
  'opaque', 'pastel', 'matte', 'cobalt',

  // Actions / Verbs (45)
  'tumble', 'glider', 'sprint', 'juggle', 'sculpt', 'launch', 'paddle',
  'wander', 'ripple', 'sketch', 'drifts', 'flinch', 'stride', 'hustle',
  'tackle', 'gather', 'polish', 'ignite', 'murmur', 'bounce', 'grumble',
  'jumble', 'fumble', 'dazzle', 'crumble', 'ramble', 'stumble', 'sizzle',
  'wobble', 'nibble', 'mumble', 'rumble', 'tickle', 'rustle', 'tangle',
  'kindle', 'mingle', 'jingle', 'ripple', 'nestle', 'guzzle', 'hustle',
  'baffle', 'rattle', 'buckle',

  // Objects / Things (50)
  'anchor', 'basket', 'candle', 'dagger', 'easel', 'fiddle', 'gadget',
  'helmet', 'jacket', 'kettle', 'lantern', 'mirror', 'napkin', 'pencil',
  'quartz', 'ribbon', 'saddle', 'thimble', 'umbrella', 'vessel', 'widget',
  'zipper', 'plank', 'goblet', 'pillow', 'socket', 'tunnel', 'bridge',
  'castle', 'hammer', 'ladder', 'market', 'needle', 'pebble', 'riddle',
  'shield', 'tablet', 'trophy', 'volume', 'wrench', 'button', 'fabric',
  'magnet', 'outlet', 'prism', 'saddle', 'satchel', 'barrel', 'crate',
  'funnel',

  // Nature (50)
  'canyon', 'desert', 'forest', 'glacier', 'harbor', 'island', 'jungle',
  'lagoon', 'meadow', 'nebula', 'ocean', 'planet', 'rapids', 'summit',
  'tundra', 'valley', 'breeze', 'canyon', 'cliff', 'delta', 'marsh',
  'ridge', 'stream', 'temple', 'arctic', 'autumn', 'blossom', 'comet',
  'dune', 'ember', 'frost', 'grove', 'lava', 'lunar', 'mist',
  'orbit', 'pine', 'reef', 'solar', 'thunder', 'trail', 'willow',
  'zenith', 'aurora', 'cavern', 'pollen', 'thorn', 'petal', 'coral',
  'spring',

  // Adjectives / Descriptors (50)
  'gentle', 'rugged', 'nimble', 'sturdy', 'clever', 'humble', 'fierce',
  'tender', 'placid', 'serene', 'crafty', 'brisk', 'dapper', 'mellow',
  'plucky', 'quirky', 'robust', 'subtle', 'witty', 'zesty', 'ample',
  'candid', 'fluent', 'jovial', 'lively', 'modest', 'polite', 'rapid',
  'silent', 'timely', 'verbal', 'absurd', 'blunt', 'dense', 'eager',
  'frugal', 'grand', 'noble', 'proud', 'regal', 'swift', 'vivid',
  'wary', 'alert', 'bold', 'calm', 'direct', 'exact', 'frank', 'lucid'
];

// Deduplicate the wordlist (some words may appear in multiple categories)
const UNIQUE_WORDLIST = [...new Set(PASSPHRASE_WORDLIST)];

/**
 * Generates a random integer between 0 (inclusive) and max (exclusive).
 * Uses crypto.getRandomValues when available, falls back to Math.random.
 * @param {number} max - Upper bound (exclusive)
 * @returns {number}
 */
function secureRandomInt(max) {
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const array = new Uint32Array(1);
    crypto.getRandomValues(array);
    return array[0] % max;
  }
  return Math.floor(Math.random() * max);
}

/**
 * Generates a string of random characters from a given charset.
 * @param {number} length - Number of characters to generate
 * @param {string} charset - Characters to sample from
 * @returns {string}
 */
function randomChars(length, charset) {
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[secureRandomInt(charset.length)];
  }
  return result;
}

/**
 * Generates password improvement suggestions based on analysis results.
 *
 * Returns exactly 3 suggestion strings, each specific to the given password,
 * referencing actual positions and characters. Suggestions are prioritized
 * by relevance and de-duplicated by category.
 *
 * @param {string} password - The password being analyzed
 * @param {Object} analysisResults - Results from password analysis
 * @param {Object} analysisResults.charsets - Character set breakdown
 * @param {boolean} analysisResults.charsets.lowercase - Has lowercase letters
 * @param {boolean} analysisResults.charsets.uppercase - Has uppercase letters
 * @param {boolean} analysisResults.charsets.digits - Has digit characters
 * @param {boolean} analysisResults.charsets.symbols - Has symbol characters
 * @param {number} analysisResults.charsets.count - Number of charsets present
 * @param {Array<Object>} analysisResults.patterns - Detected patterns
 * @param {string} analysisResults.patterns[].type - Pattern type identifier
 * @param {string} analysisResults.patterns[].description - Human-readable description
 * @param {string} analysisResults.patterns[].matched - The matched text
 * @param {string} analysisResults.patterns[].severity - 'low' | 'medium' | 'high'
 * @param {Object} analysisResults.dictionary - Dictionary match info
 * @param {boolean} analysisResults.dictionary.found - Whether dictionary words were found
 * @param {Array<Object>} analysisResults.dictionary.matches - Matched words
 * @param {string} analysisResults.dictionary.matches[].word - The matched word
 * @param {string} analysisResults.dictionary.matches[].type - Match type
 * @param {string} analysisResults.dictionary.matches[].category - Word category
 * @param {Object} analysisResults.score - Score info
 * @param {number} analysisResults.score.score - Numeric score (0-100)
 * @param {string} analysisResults.score.label - Human-readable label
 * @param {Object} analysisResults.bruteForceEntropy - Entropy info
 * @param {number} analysisResults.bruteForceEntropy.bits - Entropy in bits
 * @returns {string[]} Exactly 3 suggestion strings
 */
export function generateSuggestions(password, analysisResults) {
  const { charsets, patterns, dictionary, score } = analysisResults;
  const len = password.length;

  // We collect candidate suggestions tagged by category to avoid duplicates.
  // Each candidate: { category: string, priority: number, text: string }
  // Lower priority number = more important (shown first).
  const candidates = [];

  // ── 1. Too short (< 12 chars) ──────────────────────────────────────────────
  if (len < 12) {
    const deficit = 12 - len;
    // Pick a position roughly in the middle to suggest insertion
    const insertPos = Math.max(1, Math.floor(len / 2));
    const exampleChars = randomChars(deficit, 'abcdefghjkmnpqrstuvwxyz23456789#$%&!');
    candidates.push({
      category: 'length',
      priority: 1,
      text: `Your password is only ${len} characters. Insert ${deficit} random characters like \`${exampleChars}\` after position ${insertPos} to reach at least 12 characters.`
    });
  }

  // ── 2. Missing charsets ────────────────────────────────────────────────────
  if (!charsets.uppercase) {
    // Find a lowercase letter to suggest capitalizing
    const idx = [...password].findIndex(ch => /[a-z]/.test(ch));
    if (idx !== -1) {
      const ch = password[idx];
      candidates.push({
        category: 'charset-upper',
        priority: 2,
        text: `No uppercase letters found. Capitalize the letter at position ${idx + 1} (change \`${ch}\` to \`${ch.toUpperCase()}\`).`
      });
    } else {
      // No lowercase letters to capitalize; suggest inserting one
      const insertPos = Math.max(1, Math.floor(len / 3));
      candidates.push({
        category: 'charset-upper',
        priority: 2,
        text: `No uppercase letters found. Insert an uppercase letter like \`K\` or \`R\` at position ${insertPos}.`
      });
    }
  }

  if (!charsets.symbols) {
    // Find a character that could be replaced with a symbol
    const replaceIdx = [...password].findIndex(ch => /[a-zA-Z0-9]/.test(ch));
    const pos = replaceIdx !== -1 ? replaceIdx : Math.floor(len / 2);
    const originalChar = replaceIdx !== -1 ? password[pos] : password[pos] || '?';
    candidates.push({
      category: 'charset-symbol',
      priority: 3,
      text: `No symbols found. Replace the character \`${originalChar}\` at position ${pos + 1} with a symbol like \`#\` or \`@\`.`
    });
  }

  if (!charsets.digits) {
    const insertPos = Math.max(1, Math.floor(len * 0.6));
    candidates.push({
      category: 'charset-digit',
      priority: 3,
      text: `No digits found. Insert a random digit like \`7\` at position ${insertPos} to broaden the character set.`
    });
  }

  if (!charsets.lowercase) {
    const insertPos = Math.max(1, Math.floor(len / 2));
    candidates.push({
      category: 'charset-lower',
      priority: 3,
      text: `No lowercase letters found. Insert a lowercase letter like \`m\` or \`q\` at position ${insertPos}.`
    });
  }

  // ── 3. Dictionary word detected ────────────────────────────────────────────
  if (dictionary.found && dictionary.matches && dictionary.matches.length > 0) {
    for (const match of dictionary.matches) {
      const word = match.word;
      // Build a broken-up example: insert random chars in the middle
      const mid = Math.floor(word.length / 2);
      const insertChars = randomChars(2, '2345679!@#$%&');
      const broken = word.slice(0, mid) + insertChars + word.slice(mid);
      candidates.push({
        category: `dictionary-${word}`,
        priority: 4,
        text: `The word "${word}" was detected${match.category ? ` (${match.category})` : ''}. Break it by inserting random characters: change \`${word}\` to \`${broken}\`.`
      });
    }
  }

  // ── 4. Patterns detected ──────────────────────────────────────────────────
  if (patterns && patterns.length > 0) {
    for (const pattern of patterns) {
      const matched = pattern.matched || '';
      const patType = (pattern.type || '').toLowerCase();

      // Determine positions of the match in the original password
      const matchStart = password.indexOf(matched);
      const startPos = matchStart !== -1 ? matchStart + 1 : 1;
      const endPos = matchStart !== -1 ? matchStart + matched.length : matched.length;

      // ── 4a. Leet-speak ────────────────────────────────────────────────────
      if (patType === 'leet' || patType === 'leetspeak' || patType === 'leet-speak' ||
          (pattern.description && /leet/i.test(pattern.description))) {
        candidates.push({
          category: 'leet',
          priority: 5,
          text: `Leet-speak substitutions like \`@\` for \`a\` are well-known to attackers. Use truly random characters instead.`
        });
        continue;
      }

      // ── 4b. Common suffix ─────────────────────────────────────────────────
      if (patType === 'suffix' || patType === 'common-suffix' || patType === 'common_suffix' ||
          (pattern.description && /suffix/i.test(pattern.description))) {
        candidates.push({
          category: 'suffix',
          priority: 5,
          text: `Remove the common suffix "${matched}" and add random characters throughout the password instead.`
        });
        continue;
      }

      // ── 4c. Keyboard / sequence / repeat patterns ─────────────────────────
      const replacement = randomChars(matched.length, 'abcdefghjkmnpqrstuvwxyz23456789$#!@');
      const typeLabel = pattern.description || pattern.type || 'pattern';
      candidates.push({
        category: `pattern-${patType}-${matched}`,
        priority: 5,
        text: `The ${typeLabel} "${matched}" was detected at positions ${startPos}-${endPos}. Replace with random characters like \`${replacement}\`.`
      });
    }
  }

  // ── 5. Leet-speak fallback (check characters directly if no pattern flagged it) ──
  if (!candidates.some(c => c.category === 'leet')) {
    const leetMap = { '@': 'a', '0': 'o', '1': 'l', '3': 'e', '$': 's', '5': 's', '7': 't', '!': 'i' };
    const leetCharsFound = [...password].filter(ch => ch in leetMap);
    if (leetCharsFound.length >= 2) {
      candidates.push({
        category: 'leet',
        priority: 6,
        text: `Leet-speak substitutions like \`@\` for \`a\` are well-known to attackers. Use truly random characters instead.`
      });
    }
  }

  // ── 6. Common suffix fallback (check trailing digits/symbols) ─────────────
  if (!candidates.some(c => c.category === 'suffix')) {
    const suffixMatch = password.match(/([\d!@#$%^&*]+)$/);
    if (suffixMatch && suffixMatch[1].length >= 2) {
      const suffix = suffixMatch[1];
      // Only flag well-known suffixes
      const commonSuffixes = ['123', '1234', '12345', '123456', '1!', '!', '!!', '1', '01', '007', '69', '99', '00'];
      if (commonSuffixes.includes(suffix) || /^(\d)\1+$/.test(suffix) || /^12+3*4*5*6*7*8*9*0*$/.test(suffix)) {
        candidates.push({
          category: 'suffix',
          priority: 6,
          text: `Remove the common suffix "${suffix}" and add random characters throughout the password instead.`
        });
      }
    }
  }

  // ── 7. Strong password tips (score >= 75) ─────────────────────────────────
  if (score.score >= 75) {
    candidates.push({
      category: 'strong-longer',
      priority: 10,
      text: `Consider making it even longer — each additional random character doubles the difficulty of a brute-force attack.`
    });
    candidates.push({
      category: 'strong-unique',
      priority: 11,
      text: `Your password is strong — ensure you use a unique one per account to prevent credential-stuffing attacks.`
    });
    candidates.push({
      category: 'strong-manager',
      priority: 12,
      text: `Consider using a password manager to securely store and remember complex passwords like this.`
    });
  }

  // ── Assemble final 3 suggestions ──────────────────────────────────────────
  // Sort by priority (lower = more important), then pick 3 unique categories.
  candidates.sort((a, b) => a.priority - b.priority);

  const seen = new Set();
  const selected = [];

  for (const candidate of candidates) {
    if (selected.length >= 3) break;
    // Avoid duplicate categories (e.g., two dictionary suggestions count as same broad category)
    const broadCategory = candidate.category.split('-')[0];
    if (seen.has(candidate.category) || (broadCategory === 'charset' && seen.has(broadCategory) && selected.length >= 2)) {
      // Allow up to 2 charset suggestions, but not more
    } else {
      seen.add(candidate.category);
      seen.add(broadCategory);
      selected.push(candidate.text);
    }
  }

  // If we still don't have 3 (e.g., already strong password with few issues),
  // fill remaining slots with generic improvement tips.
  const fillers = [
    `Consider making it even longer — each additional random character doubles the difficulty of a brute-force attack.`,
    `Your password is strong — ensure you use a unique one per account to prevent credential-stuffing attacks.`,
    `Consider using a password manager to securely store and remember complex passwords like this.`,
    `Avoid reusing this password across multiple sites or services.`,
    `Enable two-factor authentication wherever possible for an extra layer of security.`
  ];

  for (const filler of fillers) {
    if (selected.length >= 3) break;
    if (!selected.includes(filler)) {
      selected.push(filler);
    }
  }

  return selected.slice(0, 3);
}

/**
 * Generates a 4-word passphrase from a curated wordlist.
 *
 * Words are selected randomly from a diverse list of ~300 common English words
 * spanning animals, foods, colors, actions, objects, nature, and adjectives.
 * Words are joined with hyphens.
 *
 * @returns {{ passphrase: string, entropy: number, wordCount: number }}
 * @property {string} passphrase - The generated passphrase (e.g., "falcon-pretzel-golden-tumble")
 * @property {number} entropy - Estimated entropy in bits: log2(wordlistSize ^ wordCount)
 * @property {number} wordCount - Number of words in the passphrase (always 4)
 *
 * @example
 * const result = generatePassphrase();
 * // {
 * //   passphrase: "walrus-canyon-nimble-kettle",
 * //   entropy: 32.78,
 * //   wordCount: 4
 * // }
 */
export function generatePassphrase() {
  const wordCount = 4;
  const wordlistSize = UNIQUE_WORDLIST.length;

  // Select 4 random words, ensuring no duplicates
  const selectedIndices = new Set();
  while (selectedIndices.size < wordCount) {
    selectedIndices.add(secureRandomInt(wordlistSize));
  }

  const words = [...selectedIndices].map(i => UNIQUE_WORDLIST[i]);
  const passphrase = words.join('-');

  // Entropy = log2(wordlistSize ^ wordCount) = wordCount * log2(wordlistSize)
  const entropy = parseFloat((wordCount * Math.log2(wordlistSize)).toFixed(2));

  return {
    passphrase,
    entropy,
    wordCount
  };
}
