/**
 * SentinelIAM — AWS IAM Policy Linter
 * Redesigned: deep navy palette, animated score ring, Space Grotesk chrome,
 * JetBrains Mono editor, tabbed right panel, Anthropic Claude AI backend.
 */

import { useState, useEffect } from 'react';
import { ValidationIssue, PolicyAnalysis } from './types.ts';

// ─── Inline SVG Icon system ────────────────────────────────────────────────
interface IconProps { size?: number; className?: string; }

const ShieldIcon = ({ size = 18 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);
const CopyIcon = ({ size = 14 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
    <path d="M8 4H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-2M8 4v4h8V4M8 4h8" />
  </svg>
);
const TrashIcon = ({ size = 14 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 6h18M19 6l-1 14H6L5 6M10 6V4h4v2" />
  </svg>
);
const SparklesIcon = ({ size = 14 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 3l1.5 4.5L18 9l-4.5 1.5L12 15l-1.5-4.5L6 9l4.5-1.5L12 3z" />
    <path d="M4 17l.75 2.25L7 20l-2.25.75L4 23l-.75-2.25L1 20l2.25-.75L4 17z" />
    <path d="M20 3l.75 2.25L23 6l-2.25.75L20 9l-.75-2.25L17 6l2.25-.75L20 3z" />
  </svg>
);
const WandIcon = ({ size = 14 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
    <path d="M15 4l5 5-9 9-5-5 9-9z" /><path d="M9 15l-5 5" /><path d="M20 4l-1-1" />
  </svg>
);
const CheckIcon = ({ size = 14 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
    <path d="M20 6L9 17l-5-5" />
  </svg>
);
const TerminalIcon = ({ size = 14 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
    <path d="M4 17l6-6-6-6M12 19h8" />
  </svg>
);
const LockIcon = ({ size = 24 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
    <path d="M19 11H5a2 2 0 00-2 2v7a2 2 0 002 2h14a2 2 0 002-2v-7a2 2 0 00-2-2zM7 11V7a5 5 0 0110 0v4" />
  </svg>
);

// ─── Sample Policy ─────────────────────────────────────────────────────────
const SAMPLE_POLICY = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:Get*",
        "s3:List*"
      ],
      "Resource": "*"
    }
  ]
}`;

// ─── Dangerous / privilege-escalation actions ──────────────────────────────
const DANGEROUS_ACTIONS = [
  'iam:CreateAccessKey', 'iam:CreateLoginProfile', 'iam:UpdateLoginProfile',
  'iam:PutUserPolicy', 'iam:AttachUserPolicy', 'iam:PutRolePolicy',
  'iam:AttachRolePolicy', 'iam:UpdateAssumeRolePolicy', 'iam:CreatePolicyVersion',
  'iam:SetDefaultPolicyVersion', 'iam:PassRole',
];

// ─── Validation Engine ─────────────────────────────────────────────────────
function validatePolicy(json: string): PolicyAnalysis {
  const issues: ValidationIssue[] = [];
  if (!json.trim()) return { isValid: false, issues, score: 0 };

  let parsed: any;
  try {
    parsed = JSON.parse(json);
  } catch (e: any) {
    return {
      isValid: false,
      issues: [{ id: 'json-syntax', severity: 'critical', message: `JSON parse error: ${e.message}`, field: 'Syntax' }],
      score: 0,
    };
  }

  if (!parsed.Version) {
    issues.push({ id: 'version', severity: 'info', message: 'Missing "Version" field. Recommended: "2012-10-17"', field: 'Version', suggestion: 'Add "Version": "2012-10-17" at the top level.' });
  }
  if (!parsed.Statement) {
    issues.push({ id: 'no-stmt', severity: 'critical', message: 'Missing required "Statement" field.', field: 'Statement' });
    return { isValid: false, issues, score: 0 };
  }

  const stmts: any[] = Array.isArray(parsed.Statement) ? parsed.Statement : [parsed.Statement];

  stmts.forEach((s: any, i: number) => {
    if (!s.Effect || !['Allow', 'Deny'].includes(s.Effect)) {
      issues.push({ id: `effect-${i}`, severity: 'critical', message: `Statement[${i}]: invalid or missing Effect "${s.Effect}".`, field: 'Effect', statementIndex: i });
    }
    if (!s.Action && !s.NotAction) {
      issues.push({ id: `action-${i}`, severity: 'critical', message: `Statement[${i}]: must have Action or NotAction.`, field: 'Action', statementIndex: i });
    }

    const actions: string[] = [].concat(s.Action || []);
    actions.forEach((a: string) => {
      if (a === '*') {
        issues.push({ id: `admin-${i}`, severity: 'critical', message: `Statement[${i}]: Action "*" grants full administrator access.`, field: 'Action', statementIndex: i, suggestion: 'Restrict to specific service actions like s3:GetObject.' });
      } else if (a?.endsWith(':*')) {
        issues.push({ id: `svc-wild-${i}-${a}`, severity: 'warning', message: `Statement[${i}]: Service-wide wildcard "${a}".`, field: 'Action', statementIndex: i, suggestion: 'Enumerate only the required actions.' });
      }
      if (DANGEROUS_ACTIONS.includes(a) && s.Effect === 'Allow') {
        issues.push({ id: `escalation-${i}-${a}`, severity: 'critical', message: `Statement[${i}]: "${a}" enables privilege escalation.`, field: 'Action', statementIndex: i, suggestion: 'Scope with Resource ARNs and Condition keys.' });
      }
    });

    if (!s.Resource && !s.NotResource) {
      issues.push({ id: `resource-${i}`, severity: 'critical', message: `Statement[${i}]: must have Resource or NotResource.`, field: 'Resource', statementIndex: i });
    }
    const resources: string[] = [].concat(s.Resource || []);
    resources.forEach((r: string) => {
      if (r === '*' && s.Effect === 'Allow') {
        issues.push({ id: `all-res-${i}`, severity: 'warning', message: `Statement[${i}]: Resource "*" applies to all AWS resources.`, field: 'Resource', statementIndex: i, suggestion: 'Specify the target ARN (e.g. arn:aws:s3:::my-bucket/*).' });
      }
    });

    if (!s.Condition && s.Effect === 'Allow' && actions.some((a: string) => DANGEROUS_ACTIONS.includes(a))) {
      issues.push({ id: `no-cond-${i}`, severity: 'warning', message: `Statement[${i}]: Sensitive action has no Condition block.`, field: 'Condition', statementIndex: i, suggestion: 'Add conditions like aws:RequestedRegion or aws:PrincipalTag.' });
    }
  });

  const crits = issues.filter(i => i.severity === 'critical').length;
  const warns = issues.filter(i => i.severity === 'warning').length;
  const score = Math.max(0, 100 - crits * 35 - warns * 10);
  return { isValid: crits === 0, issues, score, raw: parsed };
}

// ─── Score Ring Component ──────────────────────────────────────────────────
function ScoreRing({ score }: { score: number }) {
  const R = 52;
  const circumference = 2 * Math.PI * R;
  const pct = score / 100;
  const color = score >= 80 ? '#30A46C' : score >= 50 ? '#F0A500' : '#E5484D';
  const label = score >= 80 ? 'SECURE' : score >= 50 ? 'AT RISK' : 'CRITICAL';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
      <svg width="136" height="136" viewBox="0 0 136 136">
        {/* Track ring */}
        <circle cx="68" cy="68" r={R} fill="none" stroke="#1A2236" strokeWidth="10" />
        {/* Animated progress arc */}
        <circle
          cx="68" cy="68" r={R}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={`${pct * circumference} ${circumference}`}
          strokeDashoffset={circumference * 0.25}
          strokeLinecap="round"
          transform="rotate(-90 68 68)"
          style={{
            transition: 'stroke-dasharray 0.6s cubic-bezier(.4,0,.2,1), stroke 0.4s ease',
            filter: `drop-shadow(0 0 8px ${color}99)`,
          }}
        />
        <text x="68" y="64" textAnchor="middle" fill="white" fontSize="26" fontWeight="700" fontFamily="'JetBrains Mono', monospace">{score}</text>
        <text x="68" y="80" textAnchor="middle" fill="#4A5568" fontSize="9" fontFamily="'Space Grotesk', sans-serif" letterSpacing="2">/100</text>
      </svg>
      <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: 3, color, fontFamily: "'Space Grotesk', sans-serif" }}>{label}</span>
    </div>
  );
}

// ─── Issue Card Component ──────────────────────────────────────────────────
function IssueCard({ issue, index }: { issue: ValidationIssue; index: number }) {
  const palette = {
    critical: { border: '#E5484D44', bar: '#E5484D', badgeBg: '#2D1517', badgeText: '#FC8181' },
    warning:  { border: '#F0A50044', bar: '#F0A500', badgeBg: '#2D2008', badgeText: '#FBD38D' },
    info:     { border: '#4A90D944', bar: '#4A90D9', badgeBg: '#0D1F35', badgeText: '#90CDF4' },
  };
  const c = palette[issue.severity];

  return (
    <div style={{
      background: '#0D1526', border: `1px solid ${c.border}`, borderRadius: 8,
      padding: '12px 14px', position: 'relative', overflow: 'hidden',
      animation: `sentinelSlideIn 0.25s ease both`,
      animationDelay: `${index * 40}ms`,
    }}>
      {/* Left severity bar */}
      <div style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: 3, background: c.bar, borderRadius: '8px 0 0 8px' }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: 1.5, color: c.badgeText, background: c.badgeBg, padding: '2px 7px', borderRadius: 4, fontFamily: "'Space Grotesk', sans-serif", textTransform: 'uppercase' as const }}>
          {issue.severity}
        </span>
        {issue.field && <span style={{ fontSize: 9, color: '#4A5568', fontFamily: 'monospace', letterSpacing: 1 }}>• {issue.field}</span>}
        {issue.statementIndex !== undefined && (
          <span style={{ marginLeft: 'auto', fontSize: 9, color: '#2D3748', fontFamily: 'monospace' }}>STMT[{issue.statementIndex}]</span>
        )}
      </div>
      <p style={{ margin: 0, fontSize: 12, color: '#CBD5E0', lineHeight: 1.6, fontFamily: "'Space Grotesk', sans-serif" }}>{issue.message}</p>
      {issue.suggestion && (
        <p style={{ margin: '8px 0 0', fontSize: 11, color: '#718096', lineHeight: 1.5, fontFamily: "'Space Grotesk', sans-serif", paddingTop: 8, borderTop: '1px solid #1A2236' }}>
          <span style={{ color: '#F0A500', marginRight: 6 }}>→</span>{issue.suggestion}
        </p>
      )}
    </div>
  );
}

// ─── AI Panel Component ────────────────────────────────────────────────────
function AIPanel({ content, loading }: { content: string | null; loading: boolean }) {
  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '32px 0', color: '#4A5568' }}>
        <div style={{ width: 16, height: 16, border: '2px solid #F0A500', borderTopColor: 'transparent', borderRadius: '50%', animation: 'sentinelSpin 0.8s linear infinite', flexShrink: 0 }} />
        <span style={{ fontSize: 12, fontFamily: "'Space Grotesk', sans-serif" }}>Consulting AI security advisor…</span>
      </div>
    );
  }

  if (!content) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, padding: '40px 20px', textAlign: 'center' }}>
        <div style={{ width: 48, height: 48, background: '#0D1526', borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#F0A50066' }}>
          <SparklesIcon size={24} />
        </div>
        <p style={{ fontSize: 12, color: '#4A5568', lineHeight: 1.6, fontFamily: "'Space Grotesk', sans-serif" }}>
          Run AI Security Analysis to get a detailed threat assessment and remediation plan.
        </p>
      </div>
    );
  }

  // Lightweight markdown renderer: bold, inline code, headers, bullets
  const html = content
    .replace(/\*\*(.+?)\*\*/g, '<strong style="color:#F0A500">$1</strong>')
    .replace(/`(.+?)`/g, '<code style="background:#1A2236;padding:1px 5px;border-radius:3px;font-family:\'JetBrains Mono\',monospace;color:#FBD38D;font-size:11px">$1</code>')
    .replace(/^### (.+)/gm, '<p style="font-size:12px;font-weight:700;color:white;margin:14px 0 4px;letter-spacing:0.5px">$1</p>')
    .replace(/^## (.+)/gm, '<p style="font-size:13px;font-weight:700;color:white;margin:16px 0 6px">$1</p>')
    .replace(/^- (.+)/gm, '<div style="display:flex;gap:8px;margin:3px 0;font-size:12px;color:#A0AEC0;line-height:1.6"><span style="color:#F0A500;margin-top:2px">›</span><span>$1</span></div>')
    .replace(/\n\n/g, '<br/>')
    .replace(/^(?!<[pdb]|<div|<strong|<br)(.+)/gm, '<p style="font-size:12px;color:#A0AEC0;margin:4px 0;line-height:1.6">$1</p>');

  return (
    <div
      style={{ animation: 'sentinelFadeIn 0.4s ease', fontFamily: "'Space Grotesk', sans-serif" }}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}

// ─── Spinner helper ────────────────────────────────────────────────────────
function Spinner() {
  return (
    <div style={{ width: 12, height: 12, border: '2px solid #4A5568', borderTopColor: '#F0A500', borderRadius: '50%', animation: 'sentinelSpin 0.8s linear infinite', flexShrink: 0 }} />
  );
}

// ─── AI caller (Anthropic Claude via direct fetch) ─────────────────────────
async function callClaude(prompt: string): Promise<string> {
  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }],
      }),
    });
    const data = await res.json();
    return data.content?.map((b: any) => b.text || '').join('') || 'No response received.';
  } catch {
    return 'AI request failed. Please check your connection.';
  }
}

// ─── Global styles injected once ──────────────────────────────────────────
const GLOBAL_STYLES = `
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
  @keyframes sentinelSlideIn {
    from { opacity: 0; transform: translateX(12px); }
    to   { opacity: 1; transform: none; }
  }
  @keyframes sentinelFadeIn {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: none; }
  }
  @keyframes sentinelSpin  { to { transform: rotate(360deg); } }
  @keyframes sentinelPulse { 0%,100% { opacity:1 } 50% { opacity:0.4 } }
  body { background: #060B18 !important; }
  textarea:focus { outline: none; }
  textarea { caret-color: #F0A500; }
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: #1A2236; border-radius: 4px; }
`;

// ─── Main App ──────────────────────────────────────────────────────────────
export default function App() {
  const [input, setInput]         = useState(SAMPLE_POLICY);
  const [analysis, setAnalysis]   = useState<PolicyAnalysis>(() => validatePolicy(SAMPLE_POLICY));
  const [aiText, setAiText]       = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isFixing, setIsFixing]   = useState(false);
  const [copied, setCopied]       = useState(false);
  const [activeTab, setActiveTab] = useState<'issues' | 'ai'>('issues');

  useEffect(() => {
    setAnalysis(validatePolicy(input));
    setAiText(null);
  }, [input]);

  const crits = analysis.issues.filter(i => i.severity === 'critical').length;
  const warns = analysis.issues.filter(i => i.severity === 'warning').length;
  const infos = analysis.issues.filter(i => i.severity === 'info').length;
  const score = analysis.score ?? 0;

  const handleAnalyze = async () => {
    if (!analysis.raw || isAnalyzing) return;
    setIsAnalyzing(true);
    setActiveTab('ai');
    setAiText(null);
    const text = await callClaude(
      `You are an AWS IAM security expert. Analyze this IAM policy and provide a concise security report in markdown. Cover: 1) Key risks found, 2) Principle of least privilege violations, 3) Specific remediation steps. Be direct and actionable.\n\nPolicy:\n${JSON.stringify(analysis.raw, null, 2)}`
    );
    setAiText(text);
    setIsAnalyzing(false);
  };

  const handleSmartFix = async () => {
    if (isFixing) return;
    setIsFixing(true);
    const text = await callClaude(
      `You are an AWS IAM security expert applying the principle of least privilege. Fix this IAM policy to be secure. Return ONLY valid JSON, no explanation, no markdown fences.\n\nPolicy:\n${input}`
    );
    const clean = text.replace(/```json|```/g, '').trim();
    try { JSON.parse(clean); setInput(clean); } catch { /* keep original if parse fails */ }
    setIsFixing(false);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(input);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <>
      <style>{GLOBAL_STYLES}</style>
      <div style={{ height: '100vh', background: '#060B18', display: 'flex', flexDirection: 'column', fontFamily: "'Space Grotesk', sans-serif", color: '#CBD5E0', overflow: 'hidden' }}>

        {/* ── Navbar ── */}
        <nav style={{ height: 56, borderBottom: '1px solid #0D1526', background: '#080D1A', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 20px', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ width: 34, height: 34, background: '#F0A500', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#060B18', boxShadow: '0 0 20px #F0A50033' }}>
              <ShieldIcon size={18} />
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 1 }}>
              <span style={{ fontSize: 17, fontWeight: 700, color: 'white', letterSpacing: '-0.3px' }}>Sentinel</span>
              <span style={{ fontSize: 17, fontWeight: 700, color: '#F0A500', letterSpacing: '-0.3px' }}>IAM</span>
            </div>
            <div style={{ height: 16, width: 1, background: '#1A2236', margin: '0 4px' }} />
            <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#2D3748', letterSpacing: 2, textTransform: 'uppercase' as const }}>Policy Linter v2.4</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button onClick={handleCopy} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', background: '#0D1526', border: '1px solid #1A2236', borderRadius: 6, color: copied ? '#30A46C' : '#718096', fontSize: 12, fontWeight: 500, cursor: 'pointer', transition: 'all 0.2s', fontFamily: "'Space Grotesk', sans-serif" }}>
              {copied ? <CheckIcon /> : <CopyIcon />}{copied ? 'Copied' : 'Copy'}
            </button>
            <button onClick={() => { setInput(''); setAiText(null); }} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', background: '#0D1526', border: '1px solid #1A2236', borderRadius: 6, color: '#718096', fontSize: 12, fontWeight: 500, cursor: 'pointer', fontFamily: "'Space Grotesk', sans-serif" }}>
              <TrashIcon />Clear
            </button>
          </div>
        </nav>

        {/* ── Main content ── */}
        <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

          {/* Editor column */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', borderRight: '1px solid #0D1526', minWidth: 0 }}>
            {/* Editor header */}
            <div style={{ height: 40, borderBottom: '1px solid #0D1526', background: '#080D1A', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 16px', flexShrink: 0 }}>
              <div style={{ height: '100%', display: 'flex', alignItems: 'center', gap: 8, borderBottom: '2px solid #F0A500', padding: '0 4px' }}>
                <TerminalIcon /><span style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: '#F0A500', fontWeight: 500 }}>policy.json</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {crits > 0 && <span style={{ fontSize: 10, color: '#FC8181', background: '#2D1517', border: '1px solid #E5484D33', padding: '2px 8px', borderRadius: 4, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' as const }}>{crits} Critical</span>}
                {warns > 0 && <span style={{ fontSize: 10, color: '#FBD38D', background: '#2D2008', border: '1px solid #F0A50033', padding: '2px 8px', borderRadius: 4, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' as const }}>{warns} Warning</span>}
                {analysis.isValid && input.trim() && <span style={{ fontSize: 10, color: '#68D391', background: '#1A2D22', border: '1px solid #30A46C33', padding: '2px 8px', borderRadius: 4, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' as const }}>✓ Valid</span>}
              </div>
            </div>
            {/* Textarea */}
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              spellCheck={false}
              placeholder="Paste your AWS IAM JSON policy here…"
              style={{ flex: 1, padding: '20px 24px', fontFamily: "'JetBrains Mono', monospace", fontSize: 13, lineHeight: 1.7, background: '#060B18', border: 'none', color: '#A0AEC0', resize: 'none', width: '100%' }}
            />
            {/* Editor footer */}
            <div style={{ height: 32, borderTop: '1px solid #0D1526', background: '#080D1A', display: 'flex', alignItems: 'center', padding: '0 16px', gap: 20, flexShrink: 0 }}>
              <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#2D3748' }}>UTF-8</span>
              <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#2D3748' }}>LEN: {input.length}</span>
              <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#30A46C', boxShadow: '0 0 6px #30A46C88', animation: 'sentinelPulse 2s infinite' }} />
                <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#2D3748' }}>LIVE</span>
              </div>
            </div>
          </div>

          {/* Right panel */}
          <div style={{ width: 380, display: 'flex', flexDirection: 'column', background: '#080D1A', flexShrink: 0, borderLeft: '1px solid #0D1526' }}>

            {/* Score ring + stat grid + action buttons */}
            <div style={{ padding: '20px 20px 16px', borderBottom: '1px solid #0D1526' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
                <ScoreRing score={score} />
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {/* Stat grid */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 6 }}>
                    {([
                      { label: 'Critical', val: crits, color: '#E5484D' },
                      { label: 'Warning',  val: warns, color: '#F0A500' },
                      { label: 'Info',     val: infos, color: '#4A90D9' },
                    ] as const).map(s => (
                      <div key={s.label} style={{ background: '#0D1526', border: '1px solid #1A2236', borderRadius: 6, padding: '8px 10px', textAlign: 'center' as const }}>
                        <div style={{ fontSize: 18, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", color: s.val > 0 ? s.color : '#2D3748' }}>{s.val}</div>
                        <div style={{ fontSize: 9, color: '#4A5568', letterSpacing: 1, textTransform: 'uppercase' as const, marginTop: 2 }}>{s.label}</div>
                      </div>
                    ))}
                  </div>
                  {/* AI Analysis button */}
                  <button
                    onClick={handleAnalyze}
                    disabled={!analysis.raw || isAnalyzing}
                    style={{ width: '100%', padding: '8px 0', background: isAnalyzing ? '#1A2236' : '#F0A500', color: isAnalyzing ? '#4A5568' : '#060B18', border: 'none', borderRadius: 6, fontSize: 12, fontWeight: 700, cursor: isAnalyzing ? 'default' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, transition: 'all 0.2s', letterSpacing: 0.5, fontFamily: "'Space Grotesk', sans-serif" }}
                  >
                    {isAnalyzing ? <Spinner /> : <SparklesIcon />}
                    {isAnalyzing ? 'Analyzing…' : 'AI Security Analysis'}
                  </button>
                  {/* Smart Fix button */}
                  <button
                    onClick={handleSmartFix}
                    disabled={isFixing}
                    style={{ width: '100%', padding: '8px 0', background: 'transparent', color: isFixing ? '#4A5568' : '#718096', border: '1px solid #1A2236', borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: isFixing ? 'default' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, transition: 'all 0.2s', fontFamily: "'Space Grotesk', sans-serif" }}
                  >
                    {isFixing ? <Spinner /> : <WandIcon />}
                    {isFixing ? 'Applying fix…' : 'Smart Auto-Fix'}
                  </button>
                </div>
              </div>
            </div>

            {/* Tabs */}
            <div style={{ display: 'flex', borderBottom: '1px solid #0D1526', flexShrink: 0 }}>
              {([
                { id: 'issues' as const, label: `Issues${analysis.issues.length ? ` (${analysis.issues.length})` : ''}` },
                { id: 'ai'     as const, label: 'AI Advisory' },
              ]).map(t => (
                <button key={t.id} onClick={() => setActiveTab(t.id)} style={{ flex: 1, padding: '10px 0', background: 'none', border: 'none', borderBottom: activeTab === t.id ? '2px solid #F0A500' : '2px solid transparent', color: activeTab === t.id ? '#F0A500' : '#4A5568', fontSize: 11, fontWeight: 600, cursor: 'pointer', letterSpacing: 0.5, textTransform: 'uppercase' as const, fontFamily: "'Space Grotesk', sans-serif", transition: 'all 0.2s' }}>
                  {t.label}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
              {activeTab === 'issues' && (
                <>
                  {!input.trim() && (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, padding: '40px 20px', textAlign: 'center' as const }}>
                      <div style={{ width: 48, height: 48, background: '#0D1526', borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#2D3748' }}><LockIcon /></div>
                      <p style={{ fontSize: 12, color: '#4A5568', fontFamily: "'Space Grotesk', sans-serif" }}>Paste an IAM policy to begin analysis</p>
                    </div>
                  )}
                  {input.trim() && analysis.issues.length === 0 && (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, padding: '40px 20px', textAlign: 'center' as const, background: '#0D1526', border: '1px solid #30A46C22', borderRadius: 10 }}>
                      <div style={{ width: 48, height: 48, background: '#1A2D22', borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#30A46C' }}><CheckIcon size={24} /></div>
                      <div>
                        <p style={{ fontSize: 13, fontWeight: 700, color: '#30A46C', letterSpacing: 0.5, fontFamily: "'Space Grotesk', sans-serif" }}>Integrity Pass</p>
                        <p style={{ fontSize: 11, color: '#2D5640', marginTop: 4, fontFamily: "'Space Grotesk', sans-serif" }}>No logical vulnerabilities detected</p>
                      </div>
                    </div>
                  )}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {analysis.issues.map((issue, i) => <IssueCard key={issue.id} issue={issue} index={i} />)}
                  </div>
                </>
              )}
              {activeTab === 'ai' && <AIPanel content={aiText} loading={isAnalyzing} />}
            </div>
          </div>
        </div>

        {/* ── Status bar ── */}
        <div style={{ height: 28, borderTop: '1px solid #0D1526', background: '#060B18', display: 'flex', alignItems: 'center', padding: '0 16px', gap: 20, flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: crits > 0 ? '#E5484D' : '#30A46C', boxShadow: crits > 0 ? '0 0 6px #E5484D' : '0 0 6px #30A46C', animation: crits > 0 ? 'sentinelPulse 1.5s infinite' : 'none' }} />
            <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#2D3748' }}>{crits} errors · {warns} warnings · {infos} info</span>
          </div>
          <div style={{ marginLeft: 'auto', fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#1A2236' }}>SentinelIAM · AWS IAM Policy Linter</div>
        </div>

      </div>
    </>
  );
}
