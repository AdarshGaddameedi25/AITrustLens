/**
 * Shared Analysis Result Panels
 * Used by all analysis modules to render:
 *  - IntelligenceSourcesPanel (sourceStatus)
 *  - RiskFactorsPanel (riskFactors + recommendations)
 *  - CyberEduBox (contextual security education)
 */
import React from 'react';
import { motion } from 'framer-motion';
import { Database, AlertTriangle, BookOpen, Lightbulb, ShieldCheck, TriangleAlert, Activity, Server } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { GlassCard } from '@/components/ui/GlassCard';

// ── Provider display metadata ────────────────────────────────────────────────
const PROVIDER_CONFIG: Record<string, { label: string; description: string; color: string }> = {
  virusTotal:         { label: 'VirusTotal',             description: '70+ antivirus engines',              color: 'bg-indigo-100 text-indigo-700' },
  googleSafeBrowsing: { label: 'Google Safe Browsing',   description: 'Social engineering & malware database', color: 'bg-sky-100 text-sky-700' },
  urlScan:            { label: 'URLScan.io',              description: 'Dynamic behavioral scanner',          color: 'bg-purple-100 text-purple-700' },
  rdap:               { label: 'RDAP / WHOIS',            description: 'Domain registration lookup',         color: 'bg-slate-100 text-slate-700' },
  urlhausPhishing:    { label: 'URLhaus Phishing DB',     description: 'Open-source phishing blacklist',     color: 'bg-rose-100 text-rose-700' },
  dns:                { label: 'DNS Lookup',              description: 'Domain name system records',         color: 'bg-teal-100 text-teal-700' },
  spf:                { label: 'SPF Record',              description: 'Email sender policy framework',      color: 'bg-amber-100 text-amber-700' },
  dmarc:              { label: 'DMARC Record',            description: 'Email auth / reporting policy',      color: 'bg-orange-100 text-orange-700' },
  hibp:               { label: 'Have I Been Pwned',       description: 'k-anonymity breach database',       color: 'bg-rose-100 text-rose-700' },
};

const STATUS_STYLE: Record<string, string> = {
  CLEAN:       'bg-emerald-100 text-emerald-700 border border-emerald-200',
  TRUSTED:     'bg-sky-100 text-sky-700 border border-sky-200',
  VERIFIED:    'bg-sky-100 text-sky-700 border border-sky-200',
  FLAGGED:     'bg-rose-100 text-rose-700 border border-rose-200',
  SUSPICIOUS:  'bg-amber-100 text-amber-700 border border-amber-200',
  UNAVAILABLE: 'bg-slate-100 text-slate-500 border border-slate-200',
  TIMEOUT:     'bg-slate-100 text-slate-500 border border-slate-200',
  EXPOSED:     'bg-rose-100 text-rose-700 border border-rose-200',
};

// ── Cyber Education content by module ────────────────────────────────────────
type EduContent = {
  icon: React.ElementType;
  color: string;
  iconColor: string;
  title: string;
  whatHappened: string;
  whatCouldHappen: string;
  whatToDo: string[];
  expertNote: string;
};

export function getCyberEduContent(moduleType: string, result: any): EduContent {
  const level = result?.riskLevel;
  const isHigh = level === 'CRITICAL' || level === 'HIGH';
  const isMod = level === 'MODERATE';

  const MODULE_EDU: Record<string, { high: EduContent; mod: EduContent; low: EduContent }> = {
    email: {
      high: {
        icon: TriangleAlert, color: 'border-rose-200 bg-rose-50/60', iconColor: 'text-rose-500',
        title: '⚠️ Phishing Email Detected',
        whatHappened: 'AI and heuristic analysis identified multiple phishing indicators in this email: spoofed sender domains, urgency language, suspicious links, or requests for credentials. These patterns match known social engineering campaigns.',
        whatCouldHappen: 'Clicking links or attachments could: expose login credentials, install keyloggers, grant remote access to your device, or lead to financial fraud via fake invoice/payment requests.',
        whatToDo: ['Do not click any links or open any attachments in this email.', 'Do not reply or provide any personal information.', 'Report this email as phishing in your email client (Gmail/Outlook have built-in buttons).', 'If it appeared to be from your bank or a service, contact them via their official website.', 'Delete the email immediately after reporting.'],
        expertNote: 'Phishing emails often create false urgency ("Your account will be suspended in 24h!"). Legitimate organizations will never ask for your password or OTP via email.',
      },
      mod: {
        icon: Lightbulb, color: 'border-amber-200 bg-amber-50/60', iconColor: 'text-amber-500',
        title: '🔍 Suspicious Email — Verify Before Acting',
        whatHappened: 'Some phishing signals were detected but the evidence is mixed. This email may be from a legitimate sender with poor formatting, or a low-sophistication phishing attempt.',
        whatCouldHappen: 'Acting on this email without verification could lead to credential theft, unwanted subscriptions, or redirection to malicious content.',
        whatToDo: ['Verify the sender\'s actual email domain (not just the display name).', 'Hover over any links to see where they actually lead before clicking.', 'Contact the sender via a known phone number or official website to confirm legitimacy.'],
        expertNote: 'Display name spoofing is easy — "PayPal Support <phisher@random.ru>" looks like PayPal in the name field. Always check the actual domain in angle brackets.',
      },
      low: {
        icon: ShieldCheck, color: 'border-emerald-200 bg-emerald-50/60', iconColor: 'text-emerald-500',
        title: '✅ Email Appears Legitimate',
        whatHappened: 'No significant phishing indicators were found in this email\'s content, headers, or links. Sender authentication signals (SPF, DMARC) aligned with normal patterns.',
        whatCouldHappen: 'Even legitimate-looking emails can occasionally be compromised. Stay vigilant if the email asks for sensitive actions.',
        whatToDo: ['Still verify any financial requests or credential changes via official channels.', 'Don\'t share OTPs or passwords even with seemingly legitimate senders.'],
        expertNote: 'Business Email Compromise (BEC) attacks use legitimate-looking emails from real (but hacked) accounts. A clean score doesn\'t eliminate all risk for high-value targets.',
      },
    },
    scam: {
      high: {
        icon: TriangleAlert, color: 'border-rose-200 bg-rose-50/60', iconColor: 'text-rose-500',
        title: '⚠️ Scam Message Detected',
        whatHappened: 'This message contains multiple high-confidence scam indicators: prize notifications, financial requests, impersonation of brands or government agencies, or links to phishing sites.',
        whatCouldHappen: 'Responding or clicking links could: lead to financial theft via fake payments, expose your bank details, result in identity theft, or install malware on your phone.',
        whatToDo: ['Do not respond, click links, or call any numbers in this message.', 'Do not share personal information, OTPs, or bank details with the sender.', 'Block and report the sender to your carrier or messaging app.', 'Report to your national cybercrime hotline.'],
        expertNote: 'The "You\'ve won a prize!" scam is one of the oldest tricks. Real lottery/prize organizations NEVER ask you to pay fees upfront to claim winnings. That "fee" is the entire scam.',
      },
      mod: {
        icon: Lightbulb, color: 'border-amber-200 bg-amber-50/60', iconColor: 'text-amber-500',
        title: '🔍 Suspicious Message — Be Cautious',
        whatHappened: 'Some scam patterns were found. This message may use vague urgency or unusual requests that don\'t match the claimed sender\'s normal behavior.',
        whatCouldHappen: 'Engaging could expose personal information or lead to financial loss through seemingly innocent follow-up requests.',
        whatToDo: ['Do not share personal or financial information.', 'Verify the sender\'s identity through a separate, trusted channel.', 'Search online for the message text — many scams use identical scripts.'],
        expertNote: 'Scammers often start with low-pressure messages to build trust before escalating to financial requests. Early caution prevents the entire chain.',
      },
      low: {
        icon: ShieldCheck, color: 'border-emerald-200 bg-emerald-50/60', iconColor: 'text-emerald-500',
        title: '✅ Message Appears Safe',
        whatHappened: 'No major scam patterns were identified in this message. The content, tone, and structure align with legitimate communication.',
        whatCouldHappen: 'Low-risk messages can still contain links. Verify any URLs before clicking, even in trusted messages.',
        whatToDo: ['Verify any links before clicking.', 'Be cautious if follow-up messages change in tone or request personal information.'],
        expertNote: 'A clean initial message is sometimes used to establish rapport before scam content appears in follow-up messages ("long con" approach).',
      },
    },
    password: {
      high: {
        icon: TriangleAlert, color: 'border-rose-200 bg-rose-50/60', iconColor: 'text-rose-500',
        title: '⚠️ Password Exposed in Data Breaches',
        whatHappened: 'This password was found in known data breach databases via the Have I Been Pwned k-anonymity API. This means attackers have this password in their credential lists used for automated account takeover attacks.',
        whatCouldHappen: 'Attackers run "credential stuffing" attacks — trying breached username/password combinations across thousands of sites automatically. Any account using this password is at immediate risk.',
        whatToDo: ['Change this password IMMEDIATELY on ALL accounts where it is used.', 'Use a unique, random password for every account (use a password manager).', 'Enable two-factor authentication (2FA) on all critical accounts.', 'Check haveibeenpwned.com to see which breach exposed your credentials.', 'Revoke active sessions on accounts where this password was used.'],
        expertNote: 'Password reuse is the #1 cause of account takeovers. A breach at one site (e.g., a gaming forum) instantly exposes your email + banking if you use the same password.',
      },
      mod: {
        icon: Lightbulb, color: 'border-amber-200 bg-amber-50/60', iconColor: 'text-amber-500',
        title: '🔍 Weak Password — Change Recommended',
        whatHappened: 'This password was not found in breach databases but has low entropy (too short, uses common patterns, or dictionary words). It could be cracked by modern brute-force tools in minutes to hours.',
        whatCouldHappen: 'Attackers use GPU-accelerated password cracking. An 8-character lowercase password can be cracked in under 30 minutes with modern hardware.',
        whatToDo: ['Replace with a password of 16+ characters mixing upper/lower/numbers/symbols.', 'Use a passphrase: four random words are both memorable and strong.', 'Store it in a password manager (Bitwarden, 1Password).'],
        expertNote: 'Length beats complexity. "CorrectHorseBatteryStaple" is far stronger than "P@ssw0rd!" because entropy scales exponentially with length.',
      },
      low: {
        icon: ShieldCheck, color: 'border-emerald-200 bg-emerald-50/60', iconColor: 'text-emerald-500',
        title: '✅ Password Not Found in Known Breaches',
        whatHappened: 'This password was checked against millions of known breached passwords and was not found. It also shows reasonable entropy characteristics.',
        whatCouldHappen: 'Even a "not found" status doesn\'t mean 100% safe — new breaches happen daily. This result reflects databases available today.',
        whatToDo: ['Continue using unique passwords per account.', 'Enable 2FA on all critical accounts regardless.', 'Re-check periodically as new breaches are discovered.'],
        expertNote: 'The HIBP database is updated continuously as new breaches are discovered. A password safe today may appear tomorrow. Regular rotation of sensitive passwords is best practice.',
      },
    },
    privacy: {
      high: {
        icon: TriangleAlert, color: 'border-rose-200 bg-rose-50/60', iconColor: 'text-rose-500',
        title: '⚠️ High-Risk Privacy Policy',
        whatHappened: 'This privacy policy contains multiple serious red flags: selling user data to third parties, indefinite data retention, collection of sensitive personal information, and/or lack of user rights mechanisms.',
        whatCouldHappen: 'Your personal data (browsing habits, location, contacts, purchases) may be sold to data brokers, used for targeted manipulation, or stored indefinitely without your ability to delete it.',
        whatToDo: ['Consider avoiding this service or using it with minimal real personal data.', 'Use a dedicated email alias (SimpleLogin, AnonAddy) for this service.', 'Regularly review and revoke third-party app permissions.', 'Submit a data deletion request if the service is in an EU/UK jurisdiction (GDPR right to erasure).', 'Use privacy-focused browsers (Firefox + uBlock Origin) when visiting this site.'],
        expertNote: 'Data brokers buy your information from services with permissive privacy policies and resell it. This data is used for insurance pricing, employment screening, and targeted advertising without your knowledge.',
      },
      mod: {
        icon: Lightbulb, color: 'border-amber-200 bg-amber-50/60', iconColor: 'text-amber-500',
        title: '🔍 Privacy Policy Has Notable Concerns',
        whatHappened: 'Some concerning clauses were found — possible data sharing with partners, limited user control, or ambiguous retention language — though not the most extreme data-monetization practices.',
        whatCouldHappen: 'Your data may be shared with affiliated companies or used for behavioral analysis and ad targeting.',
        whatToDo: ['Read the specific flagged sections before signing up.', 'Opt out of data sharing/marketing in account settings if the option exists.', 'Use a browser extension like Privacy Badger to limit tracker activity.'],
        expertNote: '"We may share data with trusted partners" is the most common ambiguous clause. It grants unlimited sharing rights. Always check if an opt-out exists.',
      },
      low: {
        icon: ShieldCheck, color: 'border-emerald-200 bg-emerald-50/60', iconColor: 'text-emerald-500',
        title: '✅ Privacy Policy Appears Reasonable',
        whatHappened: 'No major data-selling clauses, indefinite retention, or denial of user rights were detected. The policy appears to follow reasonable data minimization practices.',
        whatCouldHappen: 'Privacy policies can change — companies sometimes update them after acquisition or strategic shifts without clear user notification.',
        whatToDo: ['Re-analyze if the company is acquired or if you receive a policy update notice.', 'Still limit the personal data you share to what\'s strictly necessary for the service.'],
        expertNote: 'Even good privacy policies can change overnight (e.g., WhatsApp\'s 2021 policy update). Subscribe to service policy change notifications and use tools like TermsChanged.com.',
      },
    },
    identity: {
      high: {
        icon: TriangleAlert, color: 'border-rose-200 bg-rose-50/60', iconColor: 'text-rose-500',
        title: '⚠️ High Identity Exposure Risk',
        whatHappened: 'DNS security checks (MX, SPF, DMARC) reveal significant email infrastructure vulnerabilities or this domain shows characteristics of spoofed/disposable/malicious registrations.',
        whatCouldHappen: 'Without SPF/DMARC, anyone can send emails pretending to be from this domain. Attackers can impersonate your organization, intercept email-based password resets, or conduct BEC (Business Email Compromise) attacks.',
        whatToDo: ['If you control this domain: implement SPF, DKIM, and DMARC records immediately.', 'Contact your domain registrar or DNS provider for guidance on email authentication records.', 'Use a domain monitoring service to alert on unauthorized email sending.', 'If this is not your domain, be wary of emails claiming to originate from it.'],
        expertNote: 'DMARC (p=reject) is the gold standard — it instructs receiving mail servers to reject any email that doesn\'t pass SPF or DKIM. Without it, email spoofing from any domain is trivial.',
      },
      mod: {
        icon: Lightbulb, color: 'border-amber-200 bg-amber-50/60', iconColor: 'text-amber-500',
        title: '🔍 Some Identity Weaknesses Found',
        whatHappened: 'Partial email authentication configurations were found — some records may be missing or misconfigured. The domain exists and has mail infrastructure but gaps remain.',
        whatCouldHappen: 'Incomplete DMARC/SPF may still allow some spoofed emails to pass through to recipients, especially if DMARC is in "none" (monitoring-only) mode.',
        whatToDo: ['Audit your SPF record for syntax errors or excessive includes.', 'Ensure DMARC policy is set to "quarantine" or "reject" rather than "none".', 'Test with free tools like MXToolbox.com or mail-tester.com.'],
        expertNote: 'DMARC "p=none" is only useful for initial monitoring — it does not protect against spoofing. You must progress to "p=quarantine" or "p=reject" for real protection.',
      },
      low: {
        icon: ShieldCheck, color: 'border-emerald-200 bg-emerald-50/60', iconColor: 'text-emerald-500',
        title: '✅ Identity & Domain Posture Looks Good',
        whatHappened: 'Email authentication records (MX, SPF, DMARC) are properly configured. The domain shows characteristics consistent with a legitimate, professionally managed organization.',
        whatCouldHappen: 'Even well-configured domains can be targeted by lookalike domain attacks (e.g., "paypa1.com" vs "paypal.com").',
        whatToDo: ['Register common typosquat domains of your organization to prevent impersonation.', 'Monitor for unauthorized certificates issued for your domain via crt.sh.'],
        expertNote: 'DMARC reporting gives you visibility into who is sending email on behalf of your domain. Configure rua/ruf addresses to receive weekly aggregate reports.',
      },
    },
    claim: {
      high: {
        icon: TriangleAlert, color: 'border-rose-200 bg-rose-50/60', iconColor: 'text-rose-500',
        title: '⚠️ Claim Rated FALSE or MISLEADING',
        whatHappened: 'Professional fact-checkers at verified publications have reviewed this claim and found it to be false, misleading, or missing critical context. Misinformation often contains a grain of truth mixed with distorted framing.',
        whatCouldHappen: 'Sharing or acting on false information can: damage public health (medical misinformation), influence elections, cause financial harm, or destroy personal/professional reputations.',
        whatToDo: ['Do not share this claim — misinformation spreads faster than corrections.', 'Read the full fact-check article from the verified sources listed.', 'If you shared this before, consider posting a correction.', 'Use lateral reading: open multiple tabs and search for what experts say about the claim topic.'],
        expertNote: 'Misinformation is designed to trigger emotional reactions (outrage, fear, excitement) to bypass critical thinking. If a claim makes you feel a strong emotion, that\'s a signal to verify it before sharing.',
      },
      mod: {
        icon: Lightbulb, color: 'border-amber-200 bg-amber-50/60', iconColor: 'text-amber-500',
        title: '🔍 Mixed or Unverified Claim',
        whatHappened: 'This claim has either conflicting fact-check verdicts across different publishers, contains a mix of true and false elements, or could not be definitively verified with available data.',
        whatCouldHappen: 'Partially false claims are particularly dangerous because the true elements lend credibility to the false parts, making it harder for readers to identify the deception.',
        whatToDo: ['Look for primary sources (scientific papers, official statements, original video).', 'Check multiple independent fact-checking organizations.', 'Consider the claim\'s context — is something technically true but being misrepresented?'],
        expertNote: '"Technically true" misinformation uses accurate facts selectively to create a false impression. Verify not just individual facts but the narrative they\'re being used to construct.',
      },
      low: {
        icon: ShieldCheck, color: 'border-emerald-200 bg-emerald-50/60', iconColor: 'text-emerald-500',
        title: '✅ Claim Appears Verified or Credible',
        whatHappened: 'Available fact-checking sources support this claim or found no evidence of it being false. The claim aligns with established consensus from credible publishers.',
        whatCouldHappen: 'Even verified claims can be taken out of context or become outdated as new evidence emerges.',
        whatToDo: ['Check when the original fact-check was published — information can change.', 'Look for primary sources even for verified claims to understand full nuance.'],
        expertNote: 'Science and facts evolve. "Verified" means it was accurate at time of fact-checking. For rapidly developing topics (health, geopolitics), re-verify with recent sources.',
      },
    },
  };

  const eduModule = MODULE_EDU[moduleType];
  if (!eduModule) {
    // Generic fallback
    return isHigh
      ? { icon: TriangleAlert, color: 'border-rose-200 bg-rose-50/60', iconColor: 'text-rose-500', title: '⚠️ High Risk Detected', whatHappened: 'Multiple risk signals were detected across security intelligence providers.', whatCouldHappen: 'Engaging with this content may expose you to security threats.', whatToDo: ['Exercise extreme caution.', 'Verify through independent sources.', 'Do not share personal information.'], expertNote: 'When in doubt, err on the side of caution and verify through trusted channels.' }
      : { icon: ShieldCheck, color: 'border-emerald-200 bg-emerald-50/60', iconColor: 'text-emerald-500', title: '✅ Appears Safe', whatHappened: 'No major risk signals were detected.', whatCouldHappen: 'Remain vigilant — no tool provides 100% certainty.', whatToDo: ['Stay alert to unusual behavior.', 'Keep software updated.'], expertNote: 'Security is a continuous practice, not a one-time check.' };
  }

  return isHigh ? eduModule.high : isMod ? eduModule.mod : eduModule.low;
}

// ── Shared Panel Components ──────────────────────────────────────────────────

interface IntelligenceSourcesPanelProps { sourceStatus: Record<string, string> | undefined; }
export function IntelligenceSourcesPanel({ sourceStatus }: IntelligenceSourcesPanelProps) {
  const entries = Object.entries(sourceStatus || {});
  if (entries.length === 0) return null;

  return (
    <GlassCard className="p-6">
      <h3 className="font-bold text-slate-800 flex items-center mb-4 border-b border-slate-100 pb-3">
        <Database className="w-4 h-4 mr-2 text-indigo-500" />
        Intelligence Sources
        <span className="ml-auto text-xs text-slate-400 font-normal">How we analyzed this</span>
      </h3>
      <div className="space-y-2.5">
        {entries.map(([key, status]) => {
          const p = PROVIDER_CONFIG[key] || { label: key.replace(/([A-Z])/g, ' $1').trim(), description: 'Security intelligence provider', color: 'bg-slate-100 text-slate-700' };
          const s = STATUS_STYLE[status] || STATUS_STYLE.UNAVAILABLE;
          return (
            <div key={key} className="flex items-center justify-between p-3 rounded-xl bg-white/50 border border-slate-100 hover:border-slate-200 transition-colors">
              <div>
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${p.color}`}>{p.label}</span>
                <p className="text-[11px] text-slate-400 mt-0.5 ml-0.5">{p.description}</p>
              </div>
              <span className={`text-[10px] font-bold uppercase px-2 py-1 rounded-lg ml-3 ${s}`}>{status}</span>
            </div>
          );
        })}
      </div>
    </GlassCard>
  );
}

interface RiskFactorsPanelProps { riskFactors: any[] | undefined; recommendations: any[] | undefined; }
export function RiskFactorsPanel({ riskFactors, recommendations }: RiskFactorsPanelProps) {
  const hasRiskFactors = riskFactors && riskFactors.length > 0;
  const hasRecs = recommendations && recommendations.length > 0;
  if (!hasRiskFactors && !hasRecs) return null;

  return (
    <GlassCard className="p-6">
      <h3 className="font-bold text-slate-800 flex items-center mb-4 border-b border-slate-100 pb-3">
        <AlertTriangle className="w-4 h-4 mr-2 text-orange-400" />
        Risk Factors & Recommendations
        <span className="ml-auto text-xs text-slate-400 font-normal">Key indicators</span>
      </h3>
      {hasRiskFactors && (
        <ul className="space-y-2 mb-4">
          {riskFactors.map((f: any, i: number) => (
            <li key={i} className="flex items-start gap-2 p-2.5 rounded-lg bg-white/50 border border-slate-100 text-sm">
              <span className={`mt-1 w-2 h-2 rounded-full flex-shrink-0 ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'bg-rose-400' : f.severity === 'MODERATE' ? 'bg-amber-400' : 'bg-emerald-300'}`} />
              <div className="flex-grow min-w-0">
                <span className="text-slate-700 font-medium truncate block">{(f.name || f.indicator || '').replace(/_/g, ' ')}</span>
                {f.source && <span className="text-[10px] text-slate-400">{f.source}</span>}
              </div>
              <div className="flex-shrink-0 flex flex-col items-end gap-0.5">
                {f.severity && <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'bg-rose-100 text-rose-700' : f.severity === 'MODERATE' ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-600'}`}>{f.severity}</span>}
                {f.contribution != null && <span className="text-[10px] text-slate-400">+{f.contribution}</span>}
              </div>
            </li>
          ))}
        </ul>
      )}

      {hasRecs && (
        <ul className="space-y-2 mt-4">
          {recommendations.slice(0, 3).map((rec: any, i: number) => (
            <li key={i} className="bg-white/50 border border-slate-100 p-2.5 rounded-lg">
              <div className="flex items-center gap-1.5 mb-1">
                <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${rec.priority === 'HIGH' ? 'bg-rose-100 text-rose-700' : rec.priority === 'MEDIUM' ? 'bg-amber-100 text-amber-800' : 'bg-sky-100 text-sky-700'}`}>{rec.priority}</span>
                <span className="font-semibold text-slate-800 text-xs">{rec.title}</span>
              </div>
              <p className="text-[11px] text-slate-600">{rec.action}</p>
            </li>
          ))}
        </ul>
      )}
    </GlassCard>
  );
}

interface CyberEduBoxProps { moduleType: string; result: any; }
export function CyberEduBox({ moduleType, result }: CyberEduBoxProps) {
  const edu = getCyberEduContent(moduleType, result);
  const EduIcon = edu.icon;
  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
      <div className={`rounded-2xl border-2 p-6 ${edu.color}`}>
        <div className="flex items-center gap-3 mb-5">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-white/70 shadow-sm">
            <EduIcon className={`w-5 h-5 ${edu.iconColor}`} />
          </div>
          <div>
            <h3 className="font-bold text-slate-900 text-base">{edu.title}</h3>
            <p className="text-xs text-slate-500 flex items-center gap-1"><BookOpen className="w-3 h-3" /> Cybersecurity Intelligence — by AITrustLens</p>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-white/60 rounded-xl p-4 border border-white">
            <h4 className="text-xs font-bold text-slate-600 uppercase tracking-wide mb-2">🔎 What Happened</h4>
            <p className="text-sm text-slate-700 leading-relaxed">{edu.whatHappened}</p>
          </div>
          <div className="bg-white/60 rounded-xl p-4 border border-white">
            <h4 className="text-xs font-bold text-slate-600 uppercase tracking-wide mb-2">⚡ What Could Happen</h4>
            <p className="text-sm text-slate-700 leading-relaxed">{edu.whatCouldHappen}</p>
          </div>
          <div className="bg-white/60 rounded-xl p-4 border border-white">
            <h4 className="text-xs font-bold text-slate-600 uppercase tracking-wide mb-2">✅ What To Do</h4>
            <ul className="space-y-1.5">
              {edu.whatToDo.map((step, i) => (
                <li key={i} className="text-sm text-slate-700 flex items-start gap-1.5">
                  <span className={`font-bold flex-shrink-0 mt-0.5 ${edu.iconColor}`}>→</span> {step}
                </li>
              ))}
            </ul>
          </div>
        </div>
        <div className="mt-4 flex items-start gap-2 bg-white/40 rounded-xl p-3 border border-white/80">
          <Lightbulb className={`w-4 h-4 flex-shrink-0 mt-0.5 ${edu.iconColor}`} />
          <p className="text-xs text-slate-600 leading-relaxed"><strong className="text-slate-800">Expert Insight:</strong> {edu.expertNote}</p>
        </div>
      </div>
    </motion.div>
  );
}

interface ScoreHeaderProps {
  result: any;
  getRiskIcon: (level: string) => React.ReactNode;
  getRiskColor: (level: string) => string;
  getRiskBadge: (level: string) => React.ReactNode;
  accentColor?: string;
}
export function ScoreHeader({ result, getRiskIcon, getRiskColor, getRiskBadge, accentColor = 'text-slate-800' }: ScoreHeaderProps) {
  return (
    <div className="flex flex-col md:flex-row items-start md:items-center justify-between border-b border-slate-100 pb-6 mb-6">
      <div className="flex items-center space-x-4 mb-4 md:mb-0">
        <div className="p-4 rounded-2xl bg-slate-50 border border-slate-100 shadow-sm">{getRiskIcon(result.riskLevel)}</div>
        <div>
          <div className="flex items-center space-x-3">
            <h2 className={`text-5xl font-black tracking-tighter ${getRiskColor(result.riskLevel)}`}>
              {result.trustScore ?? '–'}<span className="text-2xl text-slate-400 font-medium">{result.trustScore !== undefined ? '/100' : ''}</span>
            </h2>
            {getRiskBadge(result.riskLevel)}
          </div>
        </div>
      </div>
      <div className="flex flex-col items-end space-y-1.5 text-sm text-slate-500">
        <span className="flex items-center gap-1.5"><Activity className="w-3.5 h-3.5" /> Confidence: <strong className="text-slate-800">{result.confidence ?? '–'}</strong></span>
        <span className="flex items-center gap-1.5"><Database className="w-3.5 h-3.5" /> Coverage: <strong className="text-slate-800">{result.evidenceCoverage ?? '–'}%</strong></span>
        <span className="flex items-center gap-1.5"><Server className="w-3.5 h-3.5" /> Engine: <strong className="text-slate-800">RISK_ENGINE_V2</strong></span>
      </div>
    </div>
  );
}
