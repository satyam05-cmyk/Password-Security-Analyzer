/**
 * @module dictionary
 * @description Embedded password dictionaries and checker function.
 * Uses Sets for O(1) lookup against common passwords, English words,
 * Indian names, Bollywood/cricket references, and religious/cultural terms.
 */

// ---------------------------------------------------------------------------
// Dictionaries (const arrays → converted to Sets below for O(1) lookup)
// ---------------------------------------------------------------------------

/** @type {ReadonlyArray<string>} Top ~200 most common passwords */
const COMMON_PASSWORDS_LIST = [
  'password', '123456', '123456789', '12345678', '12345', '1234567',
  '1234567890', 'qwerty', 'abc123', '111111', 'password1', '1234',
  'iloveyou', 'sunshine', 'princess', 'football', 'charlie', 'shadow',
  'master', 'dragon', 'monkey', 'letmein', '696969', 'mustang', 'access',
  'batman', 'trustno1', 'superman', 'qwerty123', 'welcome', 'hello',
  'whatever', 'freedom', 'love', 'starwars', 'soccer', 'hockey', 'ranger',
  'harley', 'cheese', 'summer', 'flower', 'cookie', 'pepper', 'buster',
  'ginger', 'killer', 'george', 'tigger', 'andrea', 'admin', 'admin123',
  'passw0rd', 'pass123', 'pa55word', '654321', '666666', '121212', '123321',
  '987654321', '000000', 'login', 'baseball', 'lovely', 'rockyou', 'hottie',
  'babygirl', 'tiger', 'pussy', 'money', 'chicken', 'ashley', 'jessica',
  'daniel', 'thomas', 'jordan', 'andrew', 'joshua', 'nicole', 'hunter',
  'robert', 'bailey', 'pass', '7777777', '123abc', 'qwertyuiop', 'asdfgh',
  'asdfghjkl', 'zxcvbnm', '1q2w3e4r', '1qaz2wsx', 'michael'
];

/** @type {ReadonlyArray<string>} English words commonly found in passwords (~100) */
const COMMON_WORDS_LIST = [
  'monkey', 'dragon', 'master', 'shadow', 'sunshine', 'princess', 'football',
  'baseball', 'soccer', 'hockey', 'superman', 'batman', 'starwars', 'pokemon',
  'naruto', 'cookie', 'pepper', 'cheese', 'summer', 'winter', 'spring',
  'autumn', 'orange', 'purple', 'silver', 'golden', 'diamond', 'crystal',
  'phoenix', 'thunder', 'lightning', 'warrior', 'hunter', 'killer', 'ninja',
  'pirate', 'wizard', 'magic', 'secret', 'freedom', 'forever', 'always',
  'never', 'lovely', 'flower', 'angel', 'devil', 'ghost', 'zombie', 'vampire',
  'rocket', 'planet', 'galaxy', 'ocean', 'storm', 'blaze', 'flame', 'tiger',
  'eagle', 'wolf', 'falcon', 'panther', 'cobra', 'viper', 'mustang', 'ranger',
  'captain', 'legend', 'champion', 'alpha', 'omega', 'turbo', 'power',
  'energy', 'force', 'spirit', 'soul', 'heart', 'dream', 'star', 'moon',
  'night', 'dark', 'light', 'fire', 'ice', 'stone', 'steel', 'iron', 'blade',
  'sword', 'cyber', 'matrix', 'hacker', 'coder'
];

/** @type {ReadonlyArray<string>} Common Indian names (~80) */
const INDIAN_NAMES_LIST = [
  'rahul', 'amit', 'raj', 'rajesh', 'sanjay', 'vijay', 'arun', 'suresh',
  'mahesh', 'ramesh', 'kumar', 'deepak', 'ajay', 'sachin', 'vikas', 'pradeep',
  'aditya', 'ashish', 'gaurav', 'nikhil', 'rohit', 'rohan', 'ankit', 'arjun',
  'karan', 'sumit', 'manish', 'ravi', 'naveen', 'pankaj', 'rakesh', 'sunil',
  'vivek', 'abhishek', 'saurabh', 'varun', 'akash', 'vishal', 'shubham',
  'harsh', 'aman', 'mohit', 'tushar', 'dinesh', 'sandeep', 'sahil', 'kapil',
  'praveen', 'lokesh', 'satyam', 'priya', 'anjali', 'pooja', 'neha', 'simran',
  'priyanka', 'khushi', 'sneha', 'divya', 'swati', 'preeti', 'nisha', 'ritu',
  'archana', 'anita', 'sunita', 'kavita', 'meena', 'rekha', 'shweta',
  'deepika', 'aishwarya', 'rani', 'seema', 'sakshi', 'kajal', 'pallavi',
  'manisha', 'komal', 'tanvi', 'shruti', 'ritika'
];

/** @type {ReadonlyArray<string>} Bollywood & cricket references (~40) */
const BOLLYWOOD_CRICKET_LIST = [
  'sachin', 'virat', 'dhoni', 'kohli', 'tendulkar', 'cricket', 'ipl', 'csk',
  'rcb', 'mi', 'kkr', 'india', 'bharat', 'shahrukh', 'salman', 'amitabh',
  'bollywood', 'ddlj', 'sholay', 'srk', 'aamir', 'hrithik', 'deepika',
  'katrina', 'ranveer', 'akshay', 'ranbir', 'dangal', 'lagaan', 'dil', 'pyar',
  'ishq', 'mohabbat', 'jawan', 'pathaan', 'pushpa', 'rrr', 'baahubali',
  'kgf', 'gadar'
];

/** @type {ReadonlyArray<string>} Religious & cultural terms (~20) */
const RELIGIOUS_CULTURAL_LIST = [
  'krishna', 'ganesh', 'shiva', 'lakshmi', 'durga', 'hanuman', 'ram', 'sita',
  'radha', 'vishnu', 'parvati', 'saraswati', 'jaimatadi', 'omsairam',
  'jaishreeram', 'waheguru', 'omnamahshivaya', 'jaihanuman', 'radhekrishna',
  'mahadev'
];

// ---------------------------------------------------------------------------
// Sets for O(1) lookup
// ---------------------------------------------------------------------------

/** @type {Set<string>} */
const COMMON_PASSWORDS = new Set(COMMON_PASSWORDS_LIST);

/** @type {Set<string>} */
const COMMON_WORDS = new Set(COMMON_WORDS_LIST);

/** @type {Set<string>} */
const INDIAN_NAMES = new Set(INDIAN_NAMES_LIST);

/** @type {Set<string>} */
const BOLLYWOOD_CRICKET = new Set(BOLLYWOOD_CRICKET_LIST);

/** @type {Set<string>} */
const RELIGIOUS_CULTURAL = new Set(RELIGIOUS_CULTURAL_LIST);

/**
 * Combined mapping of every dictionary with its category label.
 * Used to iterate all dictionaries in a single pass.
 * @type {Array<{set: Set<string>, list: ReadonlyArray<string>, category: string}>}
 */
const ALL_DICTIONARIES = [
  { set: COMMON_PASSWORDS, list: COMMON_PASSWORDS_LIST, category: 'common_password' },
  { set: COMMON_WORDS,     list: COMMON_WORDS_LIST,     category: 'english_word' },
  { set: INDIAN_NAMES,     list: INDIAN_NAMES_LIST,     category: 'indian_name' },
  { set: BOLLYWOOD_CRICKET, list: BOLLYWOOD_CRICKET_LIST, category: 'bollywood_cricket' },
  { set: RELIGIOUS_CULTURAL, list: RELIGIOUS_CULTURAL_LIST, category: 'religious' },
];

// ---------------------------------------------------------------------------
// Leet-speak decoder
// ---------------------------------------------------------------------------

/**
 * Leet-speak substitution map.
 * Maps common leet characters back to their alphabetic equivalents.
 * @type {Object<string, string>}
 */
const LEET_MAP = {
  '@': 'a',
  '4': 'a',
  '3': 'e',
  '0': 'o',
  '1': 'i',
  '$': 's',
  '5': 's',
  '7': 't',
  '+': 't',
  '!': 'i',
  '#': 'h',
  '8': 'b',
};

/**
 * Decode leet-speak substitutions in a string back to plain letters.
 *
 * @param {string} str - The input string potentially containing leet characters.
 * @returns {string} The decoded string, lowercased.
 *
 * @example
 * decodeLeet('p@$$w0rd'); // => 'password'
 * decodeLeet('h4ck3r');   // => 'hacker'
 */
export function decodeLeet(str) {
  return str
    .toLowerCase()
    .split('')
    .map((ch) => LEET_MAP[ch] || ch)
    .join('');
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Minimum word length for a "contains" match to count.
 * Prevents trivially short dictionary words from flooding results.
 * @type {number}
 */
const MIN_CONTAINS_LENGTH = 4;

/**
 * Check a candidate string against every dictionary Set for exact membership.
 * Returns an array of match objects for every dictionary that contains it.
 *
 * @param {string} candidate - Lowercased candidate string.
 * @param {'exact'|'leet'|'reverse'} type - How the candidate was derived.
 * @returns {Array<{word: string, type: string, category: string}>}
 */
function checkExact(candidate, type) {
  /** @type {Array<{word: string, type: string, category: string}>} */
  const matches = [];

  for (const dict of ALL_DICTIONARIES) {
    if (dict.set.has(candidate)) {
      matches.push({ word: candidate, type, category: dict.category });
    }
  }

  return matches;
}

/**
 * Scan for any dictionary word (≥ MIN_CONTAINS_LENGTH chars) that appears
 * as a substring within the given candidate.
 *
 * @param {string} candidate - Lowercased candidate string.
 * @returns {Array<{word: string, type: 'contains', category: string}>}
 */
function checkContains(candidate) {
  /** @type {Array<{word: string, type: 'contains', category: string}>} */
  const matches = [];

  // Use a Set to avoid duplicate word+category entries
  const seen = new Set();

  for (const dict of ALL_DICTIONARIES) {
    for (const word of dict.list) {
      if (word.length < MIN_CONTAINS_LENGTH) continue;
      // Skip if the word IS the candidate (already caught by exact match)
      if (word === candidate) continue;

      if (candidate.includes(word)) {
        const key = `${word}|${dict.category}`;
        if (!seen.has(key)) {
          seen.add(key);
          matches.push({ word, type: 'contains', category: dict.category });
        }
      }
    }
  }

  return matches;
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Check a password against all embedded dictionaries.
 *
 * The check process:
 * 1. Lowercase the password → exact match against all dictionaries.
 * 2. Decode leet-speak → check the decoded version against all dictionaries.
 * 3. Reverse the password → check against all dictionaries.
 * 4. Check if any dictionary word (≥ 4 chars) is contained within the password.
 * 5. Return all matches found.
 *
 * @param {string} password - The raw password to check.
 * @returns {{ found: boolean, matches: Array<{word: string, type: 'exact'|'leet'|'contains'|'reverse', category: 'common_password'|'english_word'|'indian_name'|'bollywood_cricket'|'religious'}> }}
 *
 * @example
 * checkDictionary('Dr@g0n');
 * // => { found: true, matches: [{ word: 'dragon', type: 'leet', category: 'common_password' }, ...] }
 *
 * @example
 * checkDictionary('xYz!@#qQ');
 * // => { found: false, matches: [] }
 */
export function checkDictionary(password) {
  /** @type {Array<{word: string, type: string, category: string}>} */
  const matches = [];

  // Use a Set to deduplicate matches across checks (word|type|category)
  const seen = new Set();

  /**
   * Helper to push a match only if it hasn't been recorded yet.
   * @param {{word: string, type: string, category: string}} match
   */
  function addMatch(match) {
    const key = `${match.word}|${match.type}|${match.category}`;
    if (!seen.has(key)) {
      seen.add(key);
      matches.push(match);
    }
  }

  const lower = password.toLowerCase();

  // 1. Exact match (lowercased)
  for (const m of checkExact(lower, 'exact')) {
    addMatch(m);
  }

  // 2. Leet-speak decoded match
  const decoded = decodeLeet(password);
  if (decoded !== lower) {
    for (const m of checkExact(decoded, 'leet')) {
      addMatch(m);
    }
  }

  // 3. Reverse match
  const reversed = lower.split('').reverse().join('');
  if (reversed !== lower) {
    for (const m of checkExact(reversed, 'reverse')) {
      addMatch(m);
    }
  }

  // 4. Contains match (dictionary words ≥ 4 chars found inside the password)
  for (const m of checkContains(lower)) {
    addMatch(m);
  }

  return {
    found: matches.length > 0,
    matches,
  };
}
