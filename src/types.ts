/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface IAMPolicy {
  Version?: string;
  Statement: IAMStatement | IAMStatement[];
}

export interface IAMStatement {
  Sid?: string;
  Effect: 'Allow' | 'Deny';
  Action: string | string[];
  NotAction?: string | string[];
  Resource?: string | string[];
  NotResource?: string | string[];
  Condition?: Record<string, any>;
}

export interface ValidationIssue {
  id: string;
  severity: 'critical' | 'warning' | 'info';
  message: string;
  statementIndex?: number;
  field?: string;
  suggestion?: string;
}

export interface PolicyAnalysis {
  isValid: boolean;
  issues: ValidationIssue[];
  score?: number;
  raw?: any;
}
