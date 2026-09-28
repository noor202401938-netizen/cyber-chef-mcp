import crypto from "crypto";
import zlib from "zlib";

/**
 * Builtin high-performance security primitives matching CyberChef operations
 */
export const BuiltinChef = {
  // Encodings with structured return option
  fromBase64(input, urlSafe = false) {
    let str = String(input).trim();
    if (urlSafe) {
      str = str.replace(/-/g, "+").replace(/_/g, "/");
      while (str.length % 4) str += "=";
    }
    const buf = Buffer.from(str, "base64");
    return buf.toString("latin1");
  },

  decodeBase64(input, urlSafe = false) {
    let str = String(input).trim();
    if (urlSafe) {
      str = str.replace(/-/g, "+").replace(/_/g, "/");
      while (str.length % 4) str += "=";
    }
    const buf = Buffer.from(str, "base64");
    const hex = buf.toString("hex");
    const byteLength = buf.length;
    let isPrintable = true;
    for (let i = 0; i < buf.length; i++) {
      const b = buf[i];
      if ((b < 32 && b !== 9 && b !== 10 && b !== 13) || b === 127) {
        isPrintable = false;
        break;
      }
    }
    const utf8Str = buf.toString("utf8");
    return {
      utf8: isPrintable ? utf8Str : (utf8Str.includes("\uFFFD") ? `[Binary data: ${byteLength} bytes]` : utf8Str),
      hex,
      isPrintable,
      byteLength
    };
  },

  toBase64(input, urlSafe = false) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "latin1");
    const b64 = buf.toString("base64");
    if (urlSafe) {
      return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }
    return b64;
  },

  fromHex(input, delimiter = "None") {
    let str = String(input);
    if (delimiter === "0x") str = str.replace(/0x/gi, "");
    str = str.replace(/[^0-9a-fA-F]/g, "");
    return Buffer.from(str, "hex").toString("latin1");
  },

  decodeHex(input, delimiter = "None") {
    let str = String(input);
    if (delimiter === "0x") str = str.replace(/0x/gi, "");
    str = str.replace(/[^0-9a-fA-F]/g, "");
    const buf = Buffer.from(str, "hex");
    const hex = buf.toString("hex");
    const byteLength = buf.length;
    let isPrintable = true;
    for (let i = 0; i < buf.length; i++) {
      const b = buf[i];
      if ((b < 32 && b !== 9 && b !== 10 && b !== 13) || b === 127) {
        isPrintable = false;
        break;
      }
    }
    const utf8Str = buf.toString("utf8");
    return {
      utf8: isPrintable ? utf8Str : (utf8Str.includes("\uFFFD") ? `[Binary data: ${byteLength} bytes]` : utf8Str),
      hex,
      isPrintable,
      byteLength
    };
  },

  toHex(input, delimiter = "None") {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "latin1");
    if (delimiter === "Space") {
      return Array.from(buf).map(b => b.toString(16).padStart(2, "0")).join(" ");
    }
    if (delimiter === "0x") {
      return Array.from(buf).map(b => "0x" + b.toString(16).padStart(2, "0")).join(" ");
    }
    return buf.toString("hex");
  },

  urlDecode(input) {
    let str = String(input);
    try {
      return decodeURIComponent(str.replace(/\+/g, " "));
    } catch {
      return unescape(str);
    }
  },

  urlEncode(input, encodeAll = false) {
    const str = String(input);
    if (encodeAll) {
      return Array.from(Buffer.from(str, "utf8"))
        .map(b => "%" + b.toString(16).toUpperCase().padStart(2, "0"))
        .join("");
    }
    return encodeURIComponent(str);
  },

  // Ciphers & Transformations
  rot13(input, amount = 13) {
    const amt = ((amount % 26) + 26) % 26;
    return String(input).replace(/[a-zA-Z]/g, (c) => {
      const base = c <= "Z" ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + amt) % 26) + base);
    });
  },

  xor(input, key = "key", keyFormat = "UTF8") {
    const inBuf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "latin1");
    let keyBuf;
    if (String(keyFormat).toLowerCase() === "hex" || (typeof key === "string" && key.toLowerCase().startsWith("0x"))) {
      const cleanHex = String(key).replace(/^0x/i, "").replace(/[^0-9a-fA-F]/g, "");
      keyBuf = Buffer.from(cleanHex, "hex");
    } else {
      keyBuf = Buffer.from(key, "utf8");
    }
    if (keyBuf.length === 0) return inBuf.toString("latin1");

    const outBuf = Buffer.alloc(inBuf.length);
    for (let i = 0; i < inBuf.length; i++) {
      outBuf[i] = inBuf[i] ^ keyBuf[i % keyBuf.length];
    }
    return outBuf.toString("latin1");
  },

  aesDecrypt(input, key, iv = "", mode = "CBC") {
    try {
      const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key, "hex");
      const ivBuf = iv ? (Buffer.isBuffer(iv) ? iv : Buffer.from(iv, "hex")) : Buffer.alloc(16, 0);
      const cipherName = `aes-${keyBuf.length * 8}-${mode.toLowerCase()}`;
      const decipher = crypto.createDecipheriv(cipherName, keyBuf, ivBuf);
      let decrypted = decipher.update(Buffer.from(input, "hex"));
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      return decrypted.toString("utf8");
    } catch (err) {
      return `[AES Decrypt Error: ${err.message}]`;
    }
  },

  aesEncrypt(input, key, iv = "", mode = "CBC") {
    try {
      const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key, "hex");
      const ivBuf = iv ? (Buffer.isBuffer(iv) ? iv : Buffer.from(iv, "hex")) : Buffer.alloc(16, 0);
      const cipherName = `aes-${keyBuf.length * 8}-${mode.toLowerCase()}`;
      const cipher = crypto.createCipheriv(cipherName, keyBuf, ivBuf);
      let encrypted = cipher.update(Buffer.from(String(input), "utf8"));
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      return encrypted.toString("hex");
    } catch (err) {
      return `[AES Encrypt Error: ${err.message}]`;
    }
  },

  // Hashing
  md5(input) {
    return crypto.createHash("md5").update(Buffer.from(String(input), "latin1")).digest("hex");
  },

  sha1(input) {
    return crypto.createHash("sha1").update(Buffer.from(String(input), "latin1")).digest("hex");
  },

  sha256(input) {
    return crypto.createHash("sha256").update(Buffer.from(String(input), "latin1")).digest("hex");
  },

  sha512(input) {
    return crypto.createHash("sha512").update(Buffer.from(String(input), "latin1")).digest("hex");
  },

  analyseHash(hash) {
    const raw = String(hash).trim();

    // 1. PHC string detection: $argon2id$, $argon2i$, $argon2d$, $scrypt$, $pbkdf2$
    const phc = /^\$(argon2(?:id|i|d)|scrypt|pbkdf2(?:-sha\d+)?)\$/i.exec(raw);
    if (phc) {
      const algorithm = phc[1].toLowerCase();
      const fields = raw.split("$").filter(Boolean);
      const params = {};
      for (const f of fields) {
        if (f.includes("=")) {
          for (const kv of f.split(",")) {
            const [k, v] = kv.split("=");
            if (k && v !== undefined) {
              const num = Number(v);
              params[k] = isNaN(num) ? v : num;
            }
          }
        }
      }
      const warnings = [];
      if (algorithm.startsWith("argon2")) {
        if (params.m !== undefined && params.m < 19456) {
          warnings.push("Memory cost (m) below OWASP minimum of 19456 KiB (19 MiB)");
        }
        if (params.t !== undefined && params.t < 2) {
          warnings.push("Iteration count (t) below OWASP recommendation (t >= 2)");
        }
        if (params.p !== undefined && params.p < 1) {
          warnings.push("Parallelism (p) must be at least 1");
        }
      } else if (algorithm === "scrypt") {
        const N = params.N || (params.ln !== undefined ? 2 ** params.ln : undefined);
        if (N !== undefined && N < 65536) {
          warnings.push("CPU/memory cost (N) below OWASP recommendation of 65536 (or ln=16)");
        }
        if (params.r !== undefined && params.r < 8) {
          warnings.push("Block size (r) below recommendation of 8");
        }
      } else if (algorithm.startsWith("pbkdf2")) {
        if (params.i !== undefined && params.i < 210000) {
          warnings.push("PBKDF2 iteration count (i) below OWASP minimum of 210,000");
        }
      }

      const nonParamFields = fields.slice(1).filter(f => !f.includes("="));
      const salt = nonParamFields.length >= 2 ? nonParamFields[nonParamFields.length - 2] : (nonParamFields[0] || null);
      const hashDigest = nonParamFields.length >= 2 ? nonParamFields[nonParamFields.length - 1] : null;
      let hashLengthBytes = 0;
      if (hashDigest) {
        try {
          hashLengthBytes = Buffer.from(hashDigest, "base64").length;
        } catch {
          hashLengthBytes = hashDigest.length;
        }
      }

      const phcData = {
        algorithm,
        version: params.v,
        params,
        salt,
        hashDigest,
        hashLengthBytes
      };

      return {
        isHash: true,
        algorithm,
        version: params.v,
        params,
        salt,
        hashDigest,
        hashLengthBytes,
        phcData,
        confidence: "certain",
        probableTypes: [phc[1]],
        warnings
      };
    }

    // 2. Bcrypt prefix check: $2$, $2a$, $2b$, $2x$, $2y$
    const bcryptMatch = /^\$(2[abxy]?)\$(\d{2})\$/i.exec(raw);
    if (bcryptMatch) {
      const cost = parseInt(bcryptMatch[2], 10);
      const warnings = [];
      if (cost < 10) {
        warnings.push(`Bcrypt cost factor (${cost}) below OWASP minimum of 10`);
      }
      return {
        algorithm: "bcrypt",
        variant: `$${bcryptMatch[1]}$`,
        cost,
        probableTypes: ["Bcrypt"],
        confidence: "certain",
        warnings,
        length: raw.length
      };
    }

    const h = raw.toLowerCase();
    const len = h.length;

    // 3. Linux shadow hashes
    if (h.startsWith("$6$")) {
      return {
        algorithm: "sha512crypt",
        probableTypes: ["SHA-512 Crypt"],
        confidence: "certain",
        length: len
      };
    }
    if (h.startsWith("$5$")) {
      return {
        algorithm: "sha256crypt",
        probableTypes: ["SHA-256 Crypt"],
        confidence: "certain",
        length: len
      };
    }

    // 4. Hex digests with ranked confidence
    if (/^[0-9a-f]+$/i.test(h)) {
      if (len === 32) {
        return {
          lengthHex: 32,
          probableTypes: ["MD5", "NTLM", "MD4"],
          rankedConfidence: [
            { type: "MD5", confidence: "high", reason: "Standard 128-bit RFC 1321 hex digest" },
            { type: "NTLM", confidence: "medium", reason: "Windows NT LanMan password hash (MD4-derived)" },
            { type: "MD4", confidence: "low", reason: "Legacy 128-bit RFC 1320 digest" }
          ]
        };
      } else if (len === 40) {
        return {
          lengthHex: 40,
          probableTypes: ["SHA-1", "RIPEMD-160"],
          rankedConfidence: [
            { type: "SHA-1", confidence: "high", reason: "Standard 160-bit SHA-1 digest" },
            { type: "RIPEMD-160", confidence: "medium", reason: "160-bit European cryptographic hash" }
          ]
        };
      } else if (len === 56) {
        return {
          lengthHex: 56,
          probableTypes: ["SHA-224", "SHA3-224"],
          rankedConfidence: [
            { type: "SHA-224", confidence: "high", reason: "224-bit truncated SHA-2" },
            { type: "SHA3-224", confidence: "medium", reason: "224-bit Keccak/SHA-3 digest" }
          ]
        };
      } else if (len === 64) {
        return {
          lengthHex: 64,
          probableTypes: ["SHA-256", "SHA3-256", "BLAKE2s-256"],
          rankedConfidence: [
            { type: "SHA-256", confidence: "high", reason: "Standard 256-bit SHA-2 digest" },
            { type: "SHA3-256", confidence: "medium", reason: "Standard 256-bit Keccak/SHA-3 digest" },
            { type: "BLAKE2s-256", confidence: "medium", reason: "256-bit BLAKE2s digest" }
          ]
        };
      } else if (len === 96) {
        return {
          lengthHex: 96,
          probableTypes: ["SHA-384", "SHA3-384"],
          rankedConfidence: [
            { type: "SHA-384", confidence: "high", reason: "384-bit SHA-2 digest" },
            { type: "SHA3-384", confidence: "medium", reason: "384-bit SHA-3 digest" }
          ]
        };
      } else if (len === 128) {
        return {
          lengthHex: 128,
          probableTypes: ["SHA-512", "SHA3-512", "BLAKE2b-512"],
          rankedConfidence: [
            { type: "SHA-512", confidence: "high", reason: "Standard 512-bit SHA-2 digest" },
            { type: "SHA3-512", confidence: "medium", reason: "512-bit Keccak/SHA-3 digest" },
            { type: "BLAKE2b-512", confidence: "medium", reason: "512-bit BLAKE2b digest" }
          ]
        };
      }
    }

    return {
      hash: h,
      lengthHex: len,
      probableTypes: ["Unknown Hash / Custom Digest"]
    };
  },

  analyzeHash(hash) {
    return this.analyseHash(hash);
  },

  // Calibrated Shannon Entropy with alphabet detection
  entropy(input) {
    const str = String(input);
    if (!str.length) {
      return {
        shannonEntropy: 0,
        entropy: 0,
        bitsPerChar: 0,
        alphabet: "raw",
        maxForAlphabet: 8,
        normalizedRatio: 0,
        saturation: 0,
        totalBits: 0,
        length: 0,
        verdict: "empty",
        interpretation: "Empty input"
      };
    }

    const freqs = {};
    for (const ch of str) freqs[ch] = (freqs[ch] || 0) + 1;
    let ent = 0;
    for (const ch in freqs) {
      const p = freqs[ch] / str.length;
      ent -= p * Math.log2(p);
    }

    // Determine the representation alphabet ceiling
    const alphabet = /^[0-9a-fA-F\s]+$/.test(str)
      ? { name: "hex", max: 4 }
      : /^[A-Za-z0-9+/=_-]+$/.test(str)
      ? { name: "base64", max: 6 }
      : { name: "raw", max: 8 };

    const normalizedRatio = +(ent / alphabet.max).toFixed(4);

    let verdict = "low_entropy";
    let interpretation = "Low information density (repetitive text or structured padding)";

    if (normalizedRatio >= 0.85) {
      verdict = "encrypted_or_compressed";
      interpretation = `Near-maximal entropy (${(normalizedRatio * 100).toFixed(1)}% of ${alphabet.name} max ${alphabet.max}.0 bits/char): High probability of encrypted ciphertext, CSPRNG token, or compressed binary payload.`;
    } else if (normalizedRatio >= 0.70) {
      verdict = "high_entropy";
      interpretation = `High entropy (${(normalizedRatio * 100).toFixed(1)}% of ${alphabet.name} max ${alphabet.max}.0 bits/char): Obfuscated script, compiled binary segment, or encoded payload.`;
    } else if (normalizedRatio >= 0.45) {
      verdict = "moderate_entropy";
      interpretation = `Moderate entropy (${(normalizedRatio * 100).toFixed(1)}% of ${alphabet.name} max): Standard natural language text or source code.`;
    }

    return {
      shannonEntropy: +ent.toFixed(4),
      entropy: +ent.toFixed(4),
      bitsPerChar: +ent.toFixed(4),
      alphabet: alphabet.name,
      maxForAlphabet: alphabet.max,
      normalizedRatio,
      saturation: normalizedRatio,
      totalBits: Math.round(ent * str.length),
      length: str.length,
      verdict,
      interpretation
    };
  },

  calculateCalibratedEntropy(input) {
    return this.entropy(input);
  },

  jwtDecode(token) {
    const parts = String(token).trim().split(".");
    if (parts.length < 2) return { error: "Not a valid 3-part JWT" };
    try {
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
      return {
        header,
        payload,
        signatureHex: parts[2] ? Buffer.from(parts[2], "base64url").toString("hex") : null,
        isExpired: payload.exp ? (Date.now() / 1000 > payload.exp) : null,
        expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : null
      };
    } catch (e) {
      return { error: `Failed to parse JWT JSON: ${e.message}` };
    }
  },

  // Scoped Defanging: Only hostnames, IPs, and email @ are defanged; path and query decimals preserved
  defangUrl(input) {
    let str = String(input);

    // 1. Defang full URLs with protocol: defang protocol and host only
    str = str.replace(/\b(https?|ftp):\/\/([^\s/?#]+)([\s/?#][^\s]*)?/gi, (_, proto, host, rest = "") => {
      const defangedProto = proto.toLowerCase() === "https" ? "hxxps" : (proto.toLowerCase() === "http" ? "hxxp" : proto);
      const defangedHost = host.replace(/\./g, "[.]");
      return `${defangedProto}://${defangedHost}${rest}`;
    });

    // 2. Defang emails: change @ to [at] and host dots to [.]
    str = str.replace(/\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g, (_, user, domain) => {
      return `${user}[at]${domain.replace(/\./g, "[.]")}`;
    });

    // 3. Defang standalone IPv4 addresses (with strict 0-255 octets)
    const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/g;
    str = str.replace(ipv4Regex, (ip) => ip.replace(/\./g, "[.]"));

    return str;
  },

  refangUrl(input) {
    return String(input)
      .replace(/\bhxxps:\/\//gi, "https://")
      .replace(/\bhxxp:\/\//gi, "http://")
      .replace(/\[\.\]/g, ".")
      .replace(/\[dot\]/gi, ".")
      .replace(/\[at\]/gi, "@");
  },

  extractUrls(text) {
    const raw = String(text);
    if (!raw.includes("://")) return [];
    const urlRegex = /\b(?:https?|ftp|hxxps?):\/\/[^\s/$.?#].[^\s]*/gi;
    const matches = raw.match(urlRegex) || [];
    return [...new Set(matches)];
  },

  extractEmails(text) {
    const raw = String(text);
    if (!raw.includes("@")) return [];
    const emailRegex = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/gi;
    const matches = raw.match(emailRegex) || [];
    return [...new Set(matches)];
  },

  extractIpAddresses(text) {
    const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/g;
    const ipv6Regex = /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|\b[0-9a-fA-F]{1,4}::\b|::1\b/gi;
    const ipv4Matches = String(text).match(ipv4Regex) || [];
    const ipv6Matches = String(text).match(ipv6Regex) || [];
    return [...new Set([...ipv4Matches, ...ipv6Matches])];
  },

  // Enterprise DLP Scanner with Luhn check, IBAN, SSN, PAN, E.164, AWS keys, JWTs, Private keys
  extractDlpEntities(text) {
    const raw = String(text);
    const matches = [];

    // Helper: Luhn checksum validator for credit cards
    const isValidLuhn = (numStr) => {
      const clean = numStr.replace(/\D/g, "");
      if (clean.length < 13 || clean.length > 19) return false;
      let sum = 0;
      let shouldDouble = false;
      for (let i = clean.length - 1; i >= 0; i--) {
        let digit = parseInt(clean.charAt(i), 10);
        if (shouldDouble) {
          digit *= 2;
          if (digit > 9) digit -= 9;
        }
        sum += digit;
        shouldDouble = !shouldDouble;
      }
      return sum % 10 === 0;
    };

    // Helper: IBAN Mod-97 check
    const isValidIban = (iban) => {
      const clean = iban.replace(/[^A-Z0-9]/gi, "").toUpperCase();
      if (clean.length < 15 || clean.length > 34) return false;
      const rearranged = clean.slice(4) + clean.slice(0, 4);
      let remainder = "";
      for (const ch of rearranged) {
        const val = ch >= "A" && ch <= "Z" ? (ch.charCodeAt(0) - 55).toString() : ch;
        remainder = (BigInt(remainder + val) % 97n).toString();
      }
      return remainder === "1";
    };

    // 1. Credit Cards (Visa, Mastercard, Amex, Discover with Luhn verification)
    const ccRegex = /\b(?:[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{1,4}|[0-9]{13,19})\b/g;
    let m;
    while ((m = ccRegex.exec(raw)) !== null) {
      const digits = m[0].replace(/\D/g, "");
      if (isValidLuhn(digits)) {
        const preview = digits.slice(0, 4) + "-****-****-" + digits.slice(-4);
        matches.push({ type: "credit_card", offset: m.index, length: m[0].length, preview });
      }
    }

    // 2. US Social Security Numbers (SSN): 3-2-4 format excluding 000, 666, 900-999
    const ssnRegex = /\b(?!000|666|9\d{2})\d{3}[ -]?(?!00)\d{2}[ -]?(?!0000)\d{4}\b/g;
    while ((m = ssnRegex.exec(raw)) !== null) {
      const digits = m[0].replace(/\D/g, "");
      const preview = `***-**-${digits.slice(-4)}`;
      matches.push({ type: "us_ssn", offset: m.index, length: m[0].length, preview });
    }

    // 3. India Permanent Account Number (PAN): 5 uppercase letters, 4 digits, 1 uppercase letter
    const panRegex = /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g;
    while ((m = panRegex.exec(raw)) !== null) {
      const preview = `${m[0].slice(0, 5)}****${m[0].slice(-1)}`;
      matches.push({ type: "india_pan", offset: m.index, length: m[0].length, preview });
    }

    // 4. International Bank Account Number (IBAN)
    const ibanRegex = /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b/gi;
    while ((m = ibanRegex.exec(raw)) !== null) {
      if (isValidIban(m[0])) {
        const preview = `${m[0].slice(0, 4)}****${m[0].slice(-4)}`;
        matches.push({ type: "iban", offset: m.index, length: m[0].length, preview });
      }
    }

    // 5. E.164 International Phone Numbers: +[1-9]\d{6,14}
    const phoneRegex = /\+[1-9]\d{6,14}\b/g;
    while ((m = phoneRegex.exec(raw)) !== null) {
      const preview = `${m[0].slice(0, 4)}****${m[0].slice(-3)}`;
      matches.push({ type: "phone_e164", offset: m.index, length: m[0].length, preview });
    }

    // 6. Strict IPv4 (0-255 octet bounds; 999.999.999.999 will NOT match)
    const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/g;
    while ((m = ipv4Regex.exec(raw)) !== null) {
      const parts = m[0].split(".");
      const preview = `${parts[0]}.${parts[1]}.${parts[2]}.***`;
      matches.push({ type: "ipv4_address", offset: m.index, length: m[0].length, preview });
    }

    // 7. IPv6 Addresses
    const ipv6Regex = /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|\b[0-9a-fA-F]{1,4}::\b|::1\b/gi;
    while ((m = ipv6Regex.exec(raw)) !== null) {
      const preview = `${m[0].slice(0, 9)}...[REDACTED_IPV6]`;
      matches.push({ type: "ipv6_address", offset: m.index, length: m[0].length, preview });
    }

    // 8. AWS Access Key IDs (AKIA, ASIA, etc.)
    const awsRegex = /\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g;
    while ((m = awsRegex.exec(raw)) !== null) {
      const preview = `${m[0].slice(0, 4)}****************`;
      matches.push({ type: "aws_access_key", offset: m.index, length: m[0].length, preview });
    }

    // 9. JSON Web Tokens (JWT)
    const jwtRegex = /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;
    while ((m = jwtRegex.exec(raw)) !== null) {
      const preview = `${m[0].slice(0, 16)}...[REDACTED_JWT]`;
      matches.push({ type: "jwt", offset: m.index, length: m[0].length, preview });
    }

    // 10. Private Key Headers
    const privKeyRegex = /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g;
    while ((m = privKeyRegex.exec(raw)) !== null) {
      matches.push({ type: "private_key_header", offset: m.index, length: m[0].length, preview: "-----BEGIN PRIVATE KEY...[REDACTED]" });
    }

    // 11. URLs
    if (raw.includes("://")) {
      const urlRegex = /\b(?:https?|ftp|hxxps?):\/\/[^\s/$.?#].[^\s]*/gi;
      while ((m = urlRegex.exec(raw)) !== null) {
        matches.push({ type: "url", offset: m.index, length: m[0].length, preview: m[0].length > 40 ? m[0].slice(0, 37) + "..." : m[0] });
      }
    }

    // 12. Email Addresses
    if (raw.includes("@")) {
      const emailRegex = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/gi;
      while ((m = emailRegex.exec(raw)) !== null) {
        const atIdx = m[0].indexOf("@");
        const preview = m[0].charAt(0) + "***@" + m[0].slice(atIdx + 1);
        matches.push({ type: "email", offset: m.index, length: m[0].length, preview });
      }
    }

    // Deduplicate matches sharing identical type & offset
    const seen = new Set();
    const unique = [];
    for (const match of matches) {
      const key = `${match.type}:${match.offset}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(match);
      }
    }

    unique.sort((a, b) => a.offset - b.offset);

    const byType = {};
    for (const u of unique) {
      byType[u.type] = (byType[u.type] || 0) + 1;
    }

    return {
      totalEntities: unique.length,
      entityCountsByType: byType,
      entities: unique
    };
  },

  strings(input, minLength = 4) {
    const regex = new RegExp(`[A-Za-z0-9/\\-_.:@#%^&*()+=~<>?]{${minLength},}`, "g");
    return String(input).match(regex) || [];
  },

  gunzip(input) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "latin1");
    const decompressed = zlib.gunzipSync(buf);
    const utf8 = decompressed.toString("utf8");
    return utf8.includes("\uFFFD") ? decompressed.toString("latin1") : utf8;
  },

  gzip(input) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "utf8");
    return zlib.gzipSync(buf).toString("latin1");
  },

  inflate(input) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "latin1");
    try {
      const decompressed = zlib.inflateSync(buf);
      const utf8 = decompressed.toString("utf8");
      return utf8.includes("\uFFFD") ? decompressed.toString("latin1") : utf8;
    } catch (err) {
      // Fallback: If payload lacks zlib header (e.g. RFC 1951 raw deflate or RFC 7692), attempt rawInflate
      return this.rawInflate(buf);
    }
  },

  deflate(input) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "utf8");
    return zlib.deflateSync(buf).toString("latin1");
  },

  rawInflate(input) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "latin1");
    try {
      const decompressed = zlib.inflateRawSync(buf);
      const utf8 = decompressed.toString("utf8");
      return utf8.includes("\uFFFD") ? decompressed.toString("latin1") : utf8;
    } catch (origErr) {
      // RFC 7692 WebSocket permessage-deflate strips 00 00 ff ff tail: retry with appended tail
      try {
        const withTail = Buffer.concat([buf, Buffer.from([0x00, 0x00, 0xff, 0xff])]);
        const decompressed = zlib.inflateRawSync(withTail);
        const utf8 = decompressed.toString("utf8");
        return utf8.includes("\uFFFD") ? decompressed.toString("latin1") : utf8;
      } catch {
        throw origErr;
      }
    }
  },

  rawDeflate(input) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "utf8");
    return zlib.deflateRawSync(buf).toString("latin1");
  },

  magic(input) {
    const str = String(input).trim();
    const suggestions = [];
    const rawBuf = Buffer.from(str, "latin1");

    // 1. Direct Compression Magic Check (Gzip 1f 8b, Zlib 78 01/9c/da)
    if (rawBuf.length >= 2 && rawBuf[0] === 0x1f && rawBuf[1] === 0x8b) {
      try {
        const decompressed = zlib.gunzipSync(rawBuf).toString("utf8");
        suggestions.push({
          recipe: [{ op: "Gunzip", args: [] }],
          confidence: 0.99,
          sample: decompressed.slice(0, 100),
          description: "Gzip compressed data (RFC 1952)"
        });
      } catch {}
    } else if (rawBuf.length >= 2 && rawBuf[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(rawBuf[1])) {
      try {
        const decompressed = zlib.inflateSync(rawBuf).toString("utf8");
        suggestions.push({
          recipe: [{ op: "Zlib Inflate", args: [] }],
          confidence: 0.98,
          sample: decompressed.slice(0, 100),
          description: "Zlib compressed stream (RFC 1950)"
        });
      } catch {}
    }

    // 2. Check Base64 (both plaintext and Base64-encoded compressed streams)
    if (/^[A-Za-z0-9+/=_-]{8,}$/.test(str) && str.length % 4 === 0) {
      try {
        const decodedBuf = Buffer.from(str.replace(/-/g, "+").replace(/_/g, "/"), "base64");
        
        // Check if decoded buffer is Gzip compressed
        if (decodedBuf.length >= 2 && decodedBuf[0] === 0x1f && decodedBuf[1] === 0x8b) {
          try {
            const decompressed = zlib.gunzipSync(decodedBuf).toString("utf8");
            suggestions.push({
              recipe: [{ op: "From Base64", args: [] }, { op: "Gunzip", args: [] }],
              confidence: 0.99,
              sample: decompressed.slice(0, 100),
              description: "Base64-encoded Gzip compressed payload"
            });
          } catch {}
        } else if (decodedBuf.length >= 2 && decodedBuf[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(decodedBuf[1])) {
          try {
            const decompressed = zlib.inflateSync(decodedBuf).toString("utf8");
            suggestions.push({
              recipe: [{ op: "From Base64", args: [] }, { op: "Zlib Inflate", args: [] }],
              confidence: 0.98,
              sample: decompressed.slice(0, 100),
              description: "Base64-encoded Zlib compressed payload"
            });
          } catch {}
        } else {
          const decoded = decodedBuf.toString("utf8");
          if (/^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
            suggestions.push({
              recipe: [{ op: "From Base64", args: [] }],
              confidence: 0.95,
              sample: decoded.slice(0, 100),
              description: "Standard or URL-safe Base64 encoded plaintext"
            });
          }
        }
      } catch {}
    }

    // 3. Check Hex (both plaintext and Hex-encoded compressed streams)
    if (/^([0-9a-fA-F]{2})+$/.test(str) && str.length >= 8) {
      try {
        const decodedBuf = Buffer.from(str, "hex");
        if (decodedBuf.length >= 2 && decodedBuf[0] === 0x1f && decodedBuf[1] === 0x8b) {
          try {
            const decompressed = zlib.gunzipSync(decodedBuf).toString("utf8");
            suggestions.push({
              recipe: [{ op: "From Hex", args: ["None"] }, { op: "Gunzip", args: [] }],
              confidence: 0.99,
              sample: decompressed.slice(0, 100),
              description: "Hex-encoded Gzip compressed stream"
            });
          } catch {}
        } else {
          const decoded = decodedBuf.toString("utf8");
          if (/^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
            suggestions.push({
              recipe: [{ op: "From Hex", args: ["None"] }],
              confidence: 0.90,
              sample: decoded.slice(0, 100),
              description: "Hexadecimal byte sequence"
            });
          }
        }
      } catch {}
    }

    // 4. Check URL encoding
    if (str.includes("%") && /%[0-9a-fA-F]{2}/.test(str)) {
      try {
        const decoded = decodeURIComponent(str.replace(/\+/g, " "));
        suggestions.push({
          recipe: [{ op: "URL Decode", args: [] }],
          confidence: 0.92,
          sample: decoded.slice(0, 100),
          description: "Percent-encoded (URL) string"
        });
      } catch {}
    }

    // 5. Check JWT
    if (str.startsWith("eyJ") && str.split(".").length === 3) {
      suggestions.push({
        recipe: [{ op: "JWT Decode", args: [] }],
        confidence: 0.99,
        sample: "Header: " + Buffer.from(str.split(".")[0], "base64url").toString("utf8"),
        description: "JSON Web Token (RFC 7519)"
      });
    }

    // 6. Hash check
    if (/^[0-9a-fA-F]{32,128}$/.test(str)) {
      const hashInfo = BuiltinChef.analyseHash(str);
      suggestions.push({
        recipe: [{ op: "Analyse hash", args: [] }],
        confidence: 0.85,
        sample: hashInfo.probableTypes.join(", "),
        description: `Cryptographic digest: ${hashInfo.probableTypes.join("/")}`
      });
    }

    // 7. Single-Byte XOR Brute Force (CyberChef flagship magic feature)
    const checkBuf = (/^([0-9a-fA-F]{2})+$/.test(str) && str.length >= 16)
      ? Buffer.from(str, "hex")
      : rawBuf;
    const isHexSource = checkBuf !== rawBuf;

    if (checkBuf.length >= 8 && checkBuf.length <= 65536) {
      for (let k = 1; k < 256; k++) {
        let printable = 0;
        const xored = Buffer.alloc(checkBuf.length);
        for (let i = 0; i < checkBuf.length; i++) {
          const b = checkBuf[i] ^ k;
          xored[i] = b;
          if ((b >= 32 && b <= 126) || b === 10 || b === 13 || b === 9) {
            printable++;
          }
        }
        if (printable / checkBuf.length >= 0.88) {
          const preview = xored.toString("utf8");
          if (/powershell|cmd\.exe|https?:\/\/|flag\{|select\s+|function\s+|authorization|bearer\s+|<!doctype|<html>|\{"/i.test(preview)) {
            const recipe = isHexSource
              ? [{ op: "From Hex", args: ["None"] }, { op: "XOR", args: ["0x" + k.toString(16).padStart(2, "0"), "Hex"] }]
              : [{ op: "XOR", args: ["0x" + k.toString(16).padStart(2, "0"), "Hex"] }];
            suggestions.push({
              recipe,
              confidence: 0.93,
              sample: preview.slice(0, 100),
              description: `Single-byte XOR obfuscation (Key: 0x${k.toString(16).padStart(2, "0")})`
            });
            break;
          }
        }
      }
    }

    return {
      inputLength: str.length,
      entropy: BuiltinChef.entropy(str).shannonEntropy,
      matchesFound: suggestions.length,
      suggestions: suggestions.length ? suggestions : [{ description: "Plaintext or custom encoding with no obvious magic signature", confidence: 0.2 }]
    };
  }
};
