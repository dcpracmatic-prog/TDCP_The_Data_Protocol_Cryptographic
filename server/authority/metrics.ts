/**
 * Prometheus text-format counters for Authority ops. No secrets recorded.
 */

export class AuthorityMetrics {
  public grantsIssued = 0;
  public grantsDenied = 0;
  public revokes = 0;
  public restores = 0;
  public adminUnauthorized = 0;
  public rateLimited = 0;
  public httpRequests = 0;
  public httpErrors = 0;

  public renderPrometheus(): string {
    const lines = [
      '# HELP tdcp_authority_grants_issued Total authorization grants issued',
      '# TYPE tdcp_authority_grants_issued counter',
      `tdcp_authority_grants_issued ${this.grantsIssued}`,
      '# HELP tdcp_authority_grants_denied Total authorization requests denied',
      '# TYPE tdcp_authority_grants_denied counter',
      `tdcp_authority_grants_denied ${this.grantsDenied}`,
      '# HELP tdcp_authority_revokes Total document revoke operations',
      '# TYPE tdcp_authority_revokes counter',
      `tdcp_authority_revokes ${this.revokes}`,
      '# HELP tdcp_authority_restores Total document restore operations',
      '# TYPE tdcp_authority_restores counter',
      `tdcp_authority_restores ${this.restores}`,
      '# HELP tdcp_authority_admin_unauthorized Admin requests rejected (401/503)',
      '# TYPE tdcp_authority_admin_unauthorized counter',
      `tdcp_authority_admin_unauthorized ${this.adminUnauthorized}`,
      '# HELP tdcp_authority_rate_limited Rate-limited requests',
      '# TYPE tdcp_authority_rate_limited counter',
      `tdcp_authority_rate_limited ${this.rateLimited}`,
      '# HELP tdcp_authority_http_requests Total HTTP requests handled',
      '# TYPE tdcp_authority_http_requests counter',
      `tdcp_authority_http_requests ${this.httpRequests}`,
      '# HELP tdcp_authority_http_errors Total HTTP 5xx responses',
      '# TYPE tdcp_authority_http_errors counter',
      `tdcp_authority_http_errors ${this.httpErrors}`,
      '',
    ];
    return lines.join('\n');
  }
}
