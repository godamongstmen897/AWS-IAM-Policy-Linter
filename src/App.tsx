/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect, useMemo } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Copy, 
  Trash2, 
  Sparkles, 
  Terminal,
  ChevronRight,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  ExternalLink
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { GoogleGenAI } from "@google/genai";
import Markdown from 'react-markdown';
import { IAMPolicy, IAMStatement, ValidationIssue, PolicyAnalysis } from './types.ts';

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

export default function App() {
  const [input, setInput] = useState(SAMPLE_POLICY);
  const [analysis, setAnalysis] = useState<PolicyAnalysis>({ isValid: false, issues: [] });
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const ai = useMemo(() => new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY }), []);

  const validatePolicy = (json: string): PolicyAnalysis => {
    const issues: ValidationIssue[] = [];
    let parsed: any;

    try {
      if (!json.trim()) return { isValid: false, issues: [] };
      parsed = JSON.parse(json);
    } catch (e: any) {
      return {
        isValid: false,
        issues: [{
          id: 'json-syntax',
          severity: 'critical',
          message: `JSON Syntax Error: ${e.message}`,
        }]
      };
    }

    // Basic structure check
    if (!parsed.Statement) {
      issues.push({
        id: 'missing-statement',
        severity: 'critical',
        message: 'Policy is missing required "Statement" field.',
      });
    }

    const statements = Array.isArray(parsed.Statement) ? parsed.Statement : [parsed.Statement];

    statements.forEach((stmt: any, index) => {
      // Effect check
      if (!stmt.Effect || !['Allow', 'Deny'].includes(stmt.Effect)) {
        issues.push({
          id: `invalid-effect-${index}`,
          severity: 'critical',
          message: `Statement[${index}] has an invalid or missing "Effect". Must be "Allow" or "Deny".`,
          statementIndex: index,
          field: 'Effect'
        });
      }

      // Action check
      if (!stmt.Action && !stmt.NotAction) {
        issues.push({
          id: `missing-action-${index}`,
          severity: 'critical',
          message: `Statement[${index}] must have "Action" or "NotAction".`,
          statementIndex: index,
        });
      }

      const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
      actions.forEach((action: string) => {
        if (action === '*') {
          issues.push({
            id: `full-admin-action-${index}`,
            severity: 'critical',
            message: `Statement[${index}] provides full "*" (Administrative) access.`,
            statementIndex: index,
            field: 'Action',
            suggestion: 'Restrict actions to specific service prefixes (e.g., s3:GetObject).'
          });
        } else if (action && action.endsWith(':*')) {
          issues.push({
            id: `service-wildcard-${index}-${action}`,
            severity: 'warning',
            message: `Statement[${index}] uses a service-wide wildcard: "${action}".`,
            statementIndex: index,
            field: 'Action',
            suggestion: 'Specify only the necessary permissions.'
          });
        }
      });

      // Resource check
      if (!stmt.Resource && !stmt.NotResource) {
        issues.push({
          id: `missing-resource-${index}`,
          severity: 'critical',
          message: `Statement[${index}] must have "Resource" or "NotResource".`,
          statementIndex: index,
        });
      }

      const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
      resources.forEach((resource: string) => {
        if (resource === '*' && stmt.Effect === 'Allow') {
          issues.push({
            id: `unrestricted-resource-${index}`,
            severity: 'warning',
            message: `Statement[${index}] allows access to all resources ("*").`,
            statementIndex: index,
            field: 'Resource',
            suggestion: 'Specify the ARN of the target resource.'
          });
        }
      });

      // privilege escalation checks
      const dangerousActions = [
        'iam:CreateAccessKey',
        'iam:CreateLoginProfile',
        'iam:UpdateLoginProfile',
        'iam:PutUserPolicy',
        'iam:AttachUserPolicy',
        'iam:PutRolePolicy',
        'iam:AttachRolePolicy',
        'iam:UpdateAssumeRolePolicy',
        'iam:CreatePolicyVersion',
        'iam:SetDefaultPolicyVersion',
        'iam:PassRole'
      ];

      actions.forEach((action: string) => {
        if (dangerousActions.includes(action) && stmt.Effect === 'Allow') {
          issues.push({
            id: `potential-escalation-${index}-${action}`,
            severity: 'critical',
            message: `Potential privilege escalation: "${action}" allowed.`,
            statementIndex: index,
            field: 'Action',
            suggestion: 'Use Resource constraints and conditions to limit which users/roles can be modified.'
          });
        }
      });
    });

    return {
      isValid: issues.filter(i => i.severity === 'critical').length === 0,
      issues,
      raw: parsed
    };
  };

  useEffect(() => {
    setAnalysis(validatePolicy(input));
    setAiAnalysis(null);
  }, [input]);

  const handleAiAnalysis = async () => {
    if (!analysis.raw) return;
    setIsAnalyzing(true);
    try {
      const response = await ai.models.generateContent({
        model: "gemini-3.1-pro-preview",
        contents: `Analyze this AWS IAM Policy for security risks and provide a brief summary of findings and recommendations in markdown format. 
        Focus on the principle of least privilege.
        Policy:
        ${JSON.stringify(analysis.raw, null, 2)}`,
      });
      setAiAnalysis(response.text || "No AI feedback available.");
    } catch (error) {
      console.error(error);
      setAiAnalysis("Failed to get AI analysis. Please check your API key.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const [isFixing, setIsFixing] = useState(false);

  const handleSmartFix = async () => {
    if (!analysis.raw) return;
    setIsFixing(true);
    try {
      const response = await ai.models.generateContent({
        model: "gemini-3.1-pro-preview",
        contents: `Given the following AWS IAM policy that has security issues, provide a "Fixed" version that adheres to the principle of least privilege. 
        Only return the valid JSON policy, no other text.
        Policy:
        ${input}`,
      });
      const fixedJson = response.text?.replace(/```json|```/g, '').trim();
      if (fixedJson) {
        setInput(fixedJson);
      }
    } catch (error) {
      console.error(error);
    } finally {
      setIsFixing(false);
    }
  };

  const criticalCount = analysis.issues.filter(i => i.severity === 'critical').length;
  const warningCount = analysis.issues.filter(i => i.severity === 'warning').length;

  return (
    <div className="min-h-screen bg-[#0B0E14] text-slate-300 font-sans selection:bg-amber-500/30 flex flex-col">
      {/* Navigation */}
      <nav className="h-16 border-b border-slate-800 flex items-center justify-between px-6 bg-[#0F1219] sticky top-0 z-50 shrink-0">
        <div className="flex items-center gap-4">
          <div className="w-8 h-8 bg-amber-500 rounded-sm flex items-center justify-center text-black shadow-lg shadow-amber-500/10">
            <Shield className="w-5 h-5" />
          </div>
          <div className="flex items-center gap-3">
            <h1 className="text-lg font-semibold tracking-tight text-white flex items-center gap-1">
              Sentinel<span className="text-amber-500">IAM</span>
            </h1>
            <div className="h-4 w-[1px] bg-slate-700 hidden sm:block"></div>
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest hidden md:block">Policy Linter v2.4.0</span>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={() => navigator.clipboard.writeText(input)}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded border border-slate-700 transition-colors flex items-center gap-2"
          >
            <Copy className="w-3 h-3" />
            <span className="hidden sm:inline">Copy</span>
          </button>
          <button 
            onClick={() => setInput('')}
            className="px-4 py-2 bg-slate-800 hover:bg-red-900/30 text-red-400 text-xs font-medium rounded border border-slate-700 hover:border-red-500/50 transition-colors flex items-center gap-2"
          >
            <Trash2 className="w-3 h-3" />
            <span className="hidden sm:inline">Clear</span>
          </button>
        </div>
      </nav>

      <main className="flex-1 flex flex-col lg:flex-row overflow-hidden">
        {/* Editor Section */}
        <section className="flex-1 flex flex-col border-r border-slate-800 bg-[#0B0E14] overflow-hidden min-h-[400px]">
          <div className="h-10 border-b border-slate-800 flex items-center justify-between px-4 bg-[#13171F] shrink-0">
            <div className="flex items-center h-full">
              <div className="text-[10px] uppercase tracking-wider font-bold text-amber-500 border-b-2 border-amber-500 h-full flex items-center gap-2 px-2">
                <Terminal className="w-3 h-3" />
                policy.json
              </div>
            </div>
            <div className="flex items-center gap-3">
               {criticalCount > 0 ? (
                 <span className="flex items-center gap-1.5 text-[10px] text-red-400 font-bold px-2 py-0.5 bg-red-950/30 rounded border border-red-500/30 uppercase tracking-wider">
                    {criticalCount} Critical
                 </span>
               ) : analysis.isValid && input.trim() ? (
                <span className="flex items-center gap-1.5 text-[10px] text-green-400 font-bold px-2 py-0.5 bg-green-950/30 rounded border border-green-500/30 uppercase tracking-wider">
                    Valid Schema
                 </span>
               ) : null}
            </div>
          </div>
          
          <div className="flex-1 relative flex">
             {/* Simulated Line Numbers */}
            <div className="w-12 bg-[#0B0E14] border-r border-slate-800 flex flex-col items-center pt-6 text-slate-600 select-none font-mono text-[10px] leading-[20px] shrink-0">
               {Array.from({ length: 40 }).map((_, i) => (
                 <span key={i}>{i + 1}</span>
               ))}
            </div>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              className="flex-1 p-6 font-mono text-sm bg-transparent border-none focus:outline-none resize-none text-slate-300 placeholder-slate-700 leading-[20px]"
              placeholder="Paste your IAM JSON policy here..."
              spellCheck={false}
            />
          </div>
        </section>

        {/* Results Section */}
        <section className="w-full lg:w-96 flex flex-col bg-[#0F1219] overflow-hidden shrink-0 border-t lg:border-t-0 border-slate-800">
          <div className="p-4 border-b border-slate-800 bg-[#13171F]">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-[10px] font-bold uppercase tracking-[0.15em] text-slate-500">Analysis Results</h2>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleSmartFix}
                  disabled={!analysis.isValid || isFixing}
                  title="Auto-Fix Policy"
                  className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 disabled:opacity-30 transition-all shadow-sm"
                >
                  <ShieldCheck className={`w-3.5 h-3.5 text-green-500 ${isFixing ? 'animate-pulse' : ''}`} />
                </button>
                <button
                  onClick={handleAiAnalysis}
                  disabled={!analysis.isValid || isAnalyzing}
                  className="flex items-center gap-2 px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-black rounded text-[10px] font-bold transition-all disabled:opacity-30 uppercase tracking-wider"
                >
                  <Sparkles className={`w-3 h-3 ${isAnalyzing ? 'animate-spin' : ''}`} />
                  {isAnalyzing ? 'Analyzing' : 'AI Analysis'}
                </button>
              </div>
            </div>

            {/* Scoreboard Style Summary */}
            <div className="flex items-end justify-between bg-slate-900/50 p-4 rounded border border-slate-800/50">
              <div className="flex flex-col">
                <span className="text-[10px] font-mono text-slate-600 uppercase mb-1">Security Health</span>
                <div className="flex items-baseline gap-1">
                  <span className={`text-3xl font-mono font-bold ${criticalCount > 0 ? 'text-red-500' : 'text-green-500'}`}>
                    {Math.max(0, 100 - (criticalCount * 40 + warningCount * 10))}
                  </span>
                  <span className="text-xs text-slate-700 font-mono">/100</span>
                </div>
              </div>
              <span className={`text-[9px] font-bold px-2 py-1 rounded border uppercase tracking-wider ${
                criticalCount > 0 
                  ? 'bg-red-900/20 text-red-400 border-red-800' 
                  : 'bg-green-900/20 text-green-400 border-green-800'
              }`}>
                {criticalCount > 0 ? 'High Risk' : 'Secure'}
              </span>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto custom-scrollbar">
            <div className="p-4 space-y-4">
              {!input.trim() ? (
                  <div className="bg-slate-900/40 rounded border border-dashed border-slate-800 p-8 flex flex-col items-center justify-center text-center gap-3">
                      <div className="p-3 bg-slate-800 rounded-full">
                        <Info className="w-6 h-6 text-slate-600" />
                      </div>
                      <div>
                          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Awaiting Input</p>
                      </div>
                  </div>
              ) : (
                  <>
                    <AnimatePresence>
                      {analysis.issues.map((issue) => (
                        <motion.div
                          layout
                          initial={{ opacity: 0, x: 20 }}
                          animate={{ opacity: 1, x: 0 }}
                          exit={{ opacity: 0, x: -20 }}
                          key={issue.id}
                          className={`p-3 rounded border bg-slate-800/40 relative overflow-hidden group ${
                            issue.severity === 'critical' ? 'border-red-500/30' : issue.severity === 'warning' ? 'border-orange-500/30' : 'border-blue-500/30'
                          }`}
                        >
                          <div className={`absolute top-0 left-0 w-1 h-full ${
                             issue.severity === 'critical' ? 'bg-red-500' : issue.severity === 'warning' ? 'bg-orange-500' : 'bg-blue-500'
                          }`} />
                          
                          <div className="flex items-center justify-between mb-2">
                            <span className={`text-[9px] font-bold uppercase tracking-wider ${
                               issue.severity === 'critical' ? 'text-red-400' : issue.severity === 'warning' ? 'text-orange-400' : 'text-blue-400'
                            }`}>
                              {issue.severity} {issue.field ? `• ${issue.field}` : ''}
                            </span>
                            {issue.statementIndex !== undefined && (
                               <span className="text-[9px] font-mono text-slate-500">STMT #{issue.statementIndex}</span>
                            )}
                          </div>
                          
                          <p className="text-xs text-slate-200 font-semibold mb-2 leading-relaxed">{issue.message}</p>
                          
                          {issue.suggestion && (
                             <div className="mt-2 text-[10px] text-slate-400 leading-relaxed border-t border-slate-700/50 pt-2 flex gap-2">
                                <span className="text-amber-500 shrink-0 select-none">→</span>
                                <i>{issue.suggestion}</i>
                             </div>
                          )}
                        </motion.div>
                      ))}
                    </AnimatePresence>

                    {input.trim() && analysis.issues.length === 0 && (
                      <div className="bg-green-900/10 border border-green-500/20 p-6 rounded flex flex-col items-center text-center gap-3">
                          <CheckCircle2 className="w-8 h-8 text-green-500 opacity-50" />
                          <div>
                              <p className="text-xs font-bold text-green-400 uppercase tracking-widest">Integrity Pass</p>
                              <p className="text-[10px] text-green-700 mt-1 uppercase tracking-tight font-mono">No logical vulnerabilities detected</p>
                          </div>
                      </div>
                    )}
                  </>
              )}

              {/* AI Insights Section */}
              <AnimatePresence>
                {aiAnalysis && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="mt-6 border-t border-slate-800 pt-6"
                  >
                    <div className="flex items-center gap-2 mb-4">
                      <Sparkles className="w-3.5 h-3.5 text-amber-500" />
                      <h3 className="text-xs font-bold uppercase tracking-[0.15em] text-white">AI Security Advisory</h3>
                    </div>
                    <div className="bg-slate-900 p-4 rounded border border-slate-800 relative group overflow-hidden">
                      <div className="markdown-body prose prose-invert prose-xs max-w-none prose-ul:my-2">
                        <Markdown>{aiAnalysis}</Markdown>
                      </div>
                      {/* Decorative Element */}
                      <div className="absolute -bottom-4 -right-4 w-12 h-12 bg-amber-500/5 rounded-full blur-xl group-hover:bg-amber-500/10 transition-colors" />
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </section>
      </main>

      {/* Bottom Console / Footer */}
      <footer className="h-12 border-t border-slate-800 bg-[#0B0E14] flex items-center px-6 justify-between shrink-0">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${criticalCount > 0 ? 'bg-red-500 animate-pulse' : 'bg-slate-700'}`}></div>
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-tighter">{criticalCount} Errors</span>
          </div>
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${warningCount > 0 ? 'bg-orange-500' : 'bg-slate-700'}`}></div>
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-tighter">{warningCount} Warnings</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-500"></div>
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-tighter">System Online</span>
          </div>
        </div>
        <div className="hidden lg:flex items-center gap-6 text-[10px] font-mono text-slate-600 uppercase tracking-widest">
           <div className="flex gap-2">
              <span className="text-slate-800">ENC:</span>
              <span className="text-sky-500 font-bold">UTF-8</span>
           </div>
           <div className="flex gap-2">
              <span className="text-slate-800">LEN:</span>
              <span className="text-slate-400">{input.length}</span>
           </div>
           <div className="flex gap-2">
              <span className="text-slate-800">MEM:</span>
              <span className="text-slate-400">PAS</span>
           </div>
        </div>
      </footer>

      {/* Background Tech Overlay */}
      <div className="fixed inset-0 pointer-events-none z-[-1] opacity-[0.02]" 
           style={{ backgroundImage: 'linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)', backgroundSize: '100px 100px' }}>
      </div>
    </div>
  );
}
