// api/audit.js
import dns from "node:dns/promises";

async function resolveWithTimeout(promise, timeoutMs = 2500) {
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error("DNS query timeout")), timeoutMs);
  });
  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    clearTimeout(timer);
  }
}

async function resolveTxtSafe(host) {
  try {
    const records = await resolveWithTimeout(dns.resolveTxt(host), 2500);
    return records.map(parts => parts.join(""));
  } catch {
    return [];
  }
}

async function resolveMxSafe(domain) {
  try {
    return await resolveWithTimeout(dns.resolveMx(domain), 2500);
  } catch {
    return [];
  }
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();

  const domain = (req.query.domain || "").trim().toLowerCase();
  if (!domain || !domain.includes(".")) {
    return res.status(400).json({ error: "Invalid domain specified" });
  }

  const result = {
    domain,
    timestamp: new Date().toISOString(),
    score: 100,
    status: "PASS",
    checks: [],
  };

  // MX Records
  const mxRecords = await resolveMxSafe(domain);
  if (mxRecords.length === 0) {
    result.score -= 10;
    result.checks.push({
      name: "MX Records",
      status: "WARN",
      message: "No MX records detected. Domain cannot receive inbound replies.",
      records: [],
    });
  } else {
    result.checks.push({
      name: "MX Records",
      status: "PASS",
      message: `Discovered ${mxRecords.length} MX record(s).`,
      records: mxRecords.map(m => `${m.exchange} (Priority ${m.priority})`),
    });
  }

  // SPF
  const txtRecords = await resolveTxtSafe(domain);
  const spfRecord = txtRecords.find(r => r.startsWith("v=spf1"));
  if (!spfRecord) {
    result.score -= 30;
    result.checks.push({
      name: "SPF (Sender Policy Framework)",
      status: "FAIL",
      message: "No SPF (v=spf1) record found. High probability of spam box delivery.",
      recommendation: `Add TXT record to '${domain}': "v=spf1 include:amazonses.com ~all"`,
    });
  } else {
    const mechanisms = spfRecord.split(" ");
    const lookups = mechanisms.filter(m => /^(include|a|mx|ptr|exists|redirect):?/i.test(m)).length;
    if (lookups > 10) {
      result.score -= 20;
      result.checks.push({
        name: "SPF (Sender Policy Framework)",
        status: "FAIL",
        record: spfRecord,
        message: `Exceeds RFC 7208 10-lookup limit (${lookups} lookups). Receivers will reject mail.`,
      });
    } else {
      result.checks.push({
        name: "SPF (Sender Policy Framework)",
        status: "PASS",
        record: spfRecord,
        message: `Valid SPF record. DNS lookups: ${lookups}/10.`,
      });
    }
  }

  // DMARC
  const dmarcTxt = await resolveTxtSafe(`_dmarc.${domain}`);
  const dmarcRecord = dmarcTxt.find(r => r.startsWith("v=DMARC1"));
  if (!dmarcRecord) {
    result.score -= 35;
    result.checks.push({
      name: "DMARC Policy (_dmarc)",
      status: "FAIL",
      message: "Missing DMARC policy. Gmail and Yahoo mandate DMARC for bulk senders.",
      recommendation: `Add TXT record to '_dmarc.${domain}': "v=DMARC1; p=none; rua=mailto:dmarc@${domain}; pct=100;"`,
    });
  } else {
    const policy = (dmarcRecord.match(/p=([a-zA-Z]+)/) || [])[1]?.toLowerCase() || "none";
    if (policy === "none") {
      result.score -= 10;
      result.checks.push({
        name: "DMARC Policy (_dmarc)",
        status: "WARN",
        record: dmarcRecord,
        message: "Policy is 'p=none' (monitoring only). Recommend upgrading to 'p=quarantine' or 'p=reject'.",
      });
    } else {
      result.checks.push({
        name: "DMARC Policy (_dmarc)",
        status: "PASS",
        record: dmarcRecord,
        message: `Enforced DMARC policy: '${policy}'.`,
      });
    }
  }

  // DKIM
  const dkimTxt = await resolveTxtSafe(`resend._domainkey.${domain}`);
  const dkimRecord = dkimTxt.find(r => r.includes("v=DKIM1") || r.includes("p="));
  if (dkimRecord) {
    result.checks.push({
      name: "DKIM Signature",
      status: "PASS",
      record: dkimRecord.slice(0, 45) + "...",
      message: "DKIM key active at 'resend._domainkey'.",
    });
  } else {
    result.score -= 10;
    result.checks.push({
      name: "DKIM Signature",
      status: "WARN",
      message: "No DKIM key found at 'resend._domainkey'. Verify your DNS provider selector.",
    });
  }

  result.score = Math.max(0, Math.min(100, result.score));
  result.status = result.score >= 85 ? "EXCELLENT" : result.score >= 70 ? "GOOD" : result.score >= 50 ? "RISKY" : "CRITICAL";

  return res.status(200).json(result);
}
