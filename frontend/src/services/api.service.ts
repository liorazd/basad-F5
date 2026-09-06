import { VIPRequest, EmailNotification, F5VIP, CertInfo, AuditEntry, F5StatusVip, NodeHistoryEntry, F5Environment, IRuleVersion, PoolStats } from '@/types/vip';
import { apiConfig } from '@/config/f5.config';

export class APIService {
  private static stripSpaces(value: string | undefined | null): string {
    return (value || '').replace(/\s+/g, '');
  }

  private static normalizeRequest(request: VIPRequest): VIPRequest {
    return {
      ...request,
      vipName: this.stripSpaces(request.vipName),
      email: this.stripSpaces(request.email),
      ports: request.ports.map((port) => this.stripSpaces(port)).filter(Boolean),
      poolMembers: request.poolMembers.map((member) => ({
        ...member,
        ipAddress: this.stripSpaces(member.ipAddress),
        port: this.stripSpaces(member.port),
      })),
    };
  }

  /**
   * Convert a base64 string back into a File so FormData can transport it.
   */
  private static base64ToFile(base64: string, filename: string, mimeType: string = 'application/x-pkcs12'): File {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new File([bytes], filename, { type: mimeType });
  }

  /**
   * Store admin auth token in a cookie (HttpOnly recommended for production).
   * We use localStorage for client-side simplicity in dev.
   */
  private static readonly TOKEN_KEY = 'admin_token';
  private static readonly ACTIVE_ENVIRONMENTS_KEY = 'active_f5_environments';
  private static readonly EXPIRES_AT_KEY = 'admin_token_expires_at';
  private static readonly EFFECTIVE_EXPIRES_AT_KEY = 'admin_token_effective_expires_at';

  /**
   * Epoch seconds when the backend will hard-reject the token. Distinct
   * from the *effective* expiry (which subtracts a safety margin so the
   * client logs the user out a few minutes early).
   */
  static getTokenExpiresAt(): number | null {
    return this.readEpochKey(this.EXPIRES_AT_KEY);
  }

  /**
   * Epoch seconds when the client-side session is considered done. Always
   * <= getTokenExpiresAt(). The countdown shown to the user, and the
   * threshold the AuthContext timer uses to auto-logout.
   */
  static getEffectiveExpiresAt(): number | null {
    return this.readEpochKey(this.EFFECTIVE_EXPIRES_AT_KEY) ?? this.getTokenExpiresAt();
  }

  private static readEpochKey(key: string): number | null {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const n = parseInt(raw, 10);
    return Number.isFinite(n) ? n : null;
  }

  static setTokenExpiresAt(
    expiresAt: number | null | undefined,
    effectiveExpiresAt: number | null | undefined = undefined
  ): void {
    if (expiresAt && Number.isFinite(expiresAt)) {
      localStorage.setItem(this.EXPIRES_AT_KEY, String(expiresAt));
    } else {
      localStorage.removeItem(this.EXPIRES_AT_KEY);
    }
    const eff = effectiveExpiresAt === undefined ? expiresAt : effectiveExpiresAt;
    if (eff && Number.isFinite(eff)) {
      localStorage.setItem(this.EFFECTIVE_EXPIRES_AT_KEY, String(eff));
    } else {
      localStorage.removeItem(this.EFFECTIVE_EXPIRES_AT_KEY);
    }
  }

  /**
   * True if the effective TTL has elapsed (i.e. the client-side
   * auto-logout threshold). Use this for proactive logouts; use
   * getTokenExpiresAt() if you need the real backend deadline.
   */
  static isTokenExpired(): boolean {
    const eff = this.getEffectiveExpiresAt();
    if (!eff) return false;
    return Date.now() / 1000 >= eff;
  }

  /**
   * Login with portal credentials to authenticate with F5.
   * POST /admin/login
   */
  static async adminLogin(
    username: string,
    password: string
  ): Promise<{ token: string; environments: F5Environment[] }> {
    try {
      const response = await fetch(`/admin/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Login failed: ${response.status}`);
      }

      const data = await response.json();
      const token = data.token;

      if (!token) {
        throw new Error('No token received from server');
      }

      // Store token locally
      localStorage.setItem(this.TOKEN_KEY, token);
      localStorage.setItem(
        this.ACTIVE_ENVIRONMENTS_KEY,
        JSON.stringify(Array.isArray(data.environments) ? data.environments : [])
      );
      this.setTokenExpiresAt(
        typeof data.expires_at === 'number' ? data.expires_at : null,
        typeof data.effective_expires_at === 'number' ? data.effective_expires_at : null
      );
      return { token, environments: Array.isArray(data.environments) ? data.environments : [] };
    } catch (error) {
      console.error('Admin login error:', error);
      throw error;
    }
  }

  /**
   * Get stored admin token.
   */
  static getAdminToken(): string | null {
    return localStorage.getItem(this.TOKEN_KEY);
  }

  static getActiveEnvironments(): F5Environment[] {
    try {
      const raw = localStorage.getItem(this.ACTIVE_ENVIRONMENTS_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  /**
   * Logout and clear stored token.
   */
  static async adminLogout(): Promise<void> {
    const token = this.getAdminToken();
    // Drop local state first and unconditionally. Bailing out early on a
    // missing token used to leave the expiry keys behind, and isTokenExpired()
    // would then keep reporting an expired session that no longer exists.
    this.forgetLocalSession();
    if (!token) return;

    try {
      await fetch(`/admin/logout`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
    } catch (error) {
      console.error('Logout error:', error);
    }
  }

  /** Remove every trace of the session from localStorage. */
  private static forgetLocalSession(): void {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.ACTIVE_ENVIRONMENTS_KEY);
    localStorage.removeItem(this.EXPIRES_AT_KEY);
    localStorage.removeItem(this.EFFECTIVE_EXPIRES_AT_KEY);
  }

  /**
   * Forget the session silently. Use when the stored token turns out to be
   * unknown to the backend rather than genuinely aged out -- most commonly
   * after a backend restart, since TOKEN_STORE is in-memory and every restart
   * invalidates tokens the browser still holds for the full 8h TTL.
   */
  static clearSession(): void {
    void this.adminLogout();
  }

  /**
   * Wipe the server-side disk + memory cache so the next request hits F5 live.
   * Admin-only.
   */
  static async clearServerCache(): Promise<{ envs_cleared: number }> {
    const token = this.getAdminToken();
    if (!token) throw new Error('Admin token required');
    const res = await fetch(`/cache/clear`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    this.handleUnauthorized(res);
    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || `HTTP ${res.status}`);
    }
    const data = await res.json();
    return { envs_cleared: data.envs_cleared ?? 0 };
  }

  /**
   * Clear the local token and bounce to /admin so the user sees the login
   * form instead of an empty page when the portal token expires mid-session.
   */
  private static handleUnauthorized(response: Response): void {
    if (response.status === 401) {
      this.expireSession();
      throw new Error('Unauthorized. Please log in again.');
    }
  }

  /**
   * Drop the token and bounce to /admin. Safe to call from anywhere that
   * detects an expired session (pre-flight TTL check, AuthContext timer,
   * or a real 401 response).
   */
  static expireSession(): void {
    const hadSession = Boolean(this.getAdminToken());
    void this.adminLogout();
    if (typeof window === 'undefined') return;
    // No token means nothing expired -- an anonymous visitor just hit an
    // endpoint that needs a login. Bouncing them to a red "session expired"
    // banner is a lie, so leave them where they are.
    if (!hadSession) return;
    if (window.location.pathname === '/admin') return;
    window.location.href = '/admin?session_expired=1';
  }

  /**
   * Throws Unauthorized if the locally-known token TTL has elapsed, so we
   * don't waste a roundtrip making a doomed request. Returns silently when
   * no TTL is known.
   */
  private static guardTokenExpiry(): void {
    if (this.isTokenExpired()) {
      this.expireSession();
      throw new Error('Unauthorized. Please log in again.');
    }
  }

  private static async throwHttpError(response: Response, fallback: string): Promise<never> {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || fallback);
  }

  private static async streamNdjson(
    url: string,
    onEvent: (event: Record<string, unknown>) => void,
    signal?: AbortSignal,
    credentials?: RequestCredentials,
    requireToken = true
  ): Promise<void> {
    if (requireToken) this.guardTokenExpiry();
    const token = this.getAdminToken();
    if (requireToken && !token) throw new Error('Not authenticated. Please login first.');
    const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
    const response = await fetch(url, {
      headers,
      signal,
      credentials,
    });
    if (response.status === 401 && requireToken) {
      this.handleUnauthorized(response);
    }
    if (!response.ok) {
      await this.throwHttpError(response, `Request failed: ${response.status}`);
    }
    if (!response.body) {
      throw new Error('Streaming is not supported by this browser.');
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        const event = JSON.parse(trimmed) as Record<string, unknown>;
        if (event.event === 'error') {
          if (event.auth_expired && this.getAdminToken()) this.expireSession();
          throw new Error(typeof event.error === 'string' ? event.error : 'Streaming request failed');
        }
        onEvent(event);
      }
    }

    const tail = buffer.trim();
    if (tail) {
      const event = JSON.parse(tail) as Record<string, unknown>;
      if (event.event === 'error') {
        if (event.auth_expired && this.getAdminToken()) this.expireSession();
        throw new Error(typeof event.error === 'string' ? event.error : 'Streaming request failed');
      }
      onEvent(event);
    }
  }

  /**
   * Submit VIP request to backend. Requires admin token.
   * POST /vipcreation
   */
  static async submitVIPRequest(
    request: VIPRequest,
    onUploadProgress?: (percent: number) => void
  ): Promise<any> {
    const normalizedRequest = this.normalizeRequest(request);
    const token = this.getAdminToken();
    if (!token) {
      throw new Error('Not authenticated. Please login first.');
    }

    const formData = new FormData();
    formData.append('vip_name', normalizedRequest.vipName);
    formData.append('email', normalizedRequest.email);
    formData.append('ports', JSON.stringify(normalizedRequest.ports));
    formData.append('ssl', normalizedRequest.ssl.toString());
    formData.append('require_sni', normalizedRequest.requireSni ? 'true' : 'false');
    formData.append(
      'pool_members',
      JSON.stringify(
        normalizedRequest.poolMembers.map((pm) => ({
          ip_address: pm.ipAddress,
          port: pm.port,
        }))
      )
    );

    if (normalizedRequest.ssl) {
      // Resolve the PFX payload (either live File or rebuilt from base64)
      let pfxFileToSend = normalizedRequest.pfxFile;
      if (!pfxFileToSend && normalizedRequest.pfxFileBase64) {
        pfxFileToSend = this.base64ToFile(
          normalizedRequest.pfxFileBase64,
          normalizedRequest.pfxFileName || 'certificate.pfx',
          normalizedRequest.pfxFileType || 'application/x-pkcs12'
        );
      }

      if (!pfxFileToSend) {
        throw new Error('SSL is enabled but no PFX file is available to send.');
      }

      if (!(pfxFileToSend instanceof Blob)) {
        throw new Error('PFX payload is not a valid file/blob.');
      }

      console.log('[DEBUG] Adding PFX file to FormData:', {
        name: (pfxFileToSend as File).name || normalizedRequest.pfxFileName || 'certificate.pfx',
        size: pfxFileToSend.size,
        type: pfxFileToSend.type,
      });

      const filename = (pfxFileToSend as File).name || normalizedRequest.pfxFileName || 'certificate.pfx';
      formData.append('pfx_file', pfxFileToSend, filename);
      formData.append('pfx_password', normalizedRequest.pfxPassword || '');
    }

    // Log FormData contents for debugging
    this.logFormData(formData);

    const url = `/vipcreation`;

    // Use native fetch + FormData instead of axios (guaranteed multipart support)
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          // do NOT set Content-Type; let browser set multipart/form-data boundary
        },
        body: formData,
      });

      console.log('[DEBUG] Fetch response status:', response.status);

      this.handleUnauthorized(response);

      if (!response.ok) {
        const text = await response.text().catch(() => '');
        let errorMsg = `VIP creation failed: ${response.status}`;
        try {
          const errorData = JSON.parse(text);
          errorMsg = errorData.error || errorMsg;
        } catch {
          if (text) errorMsg = text;
        }
        throw new Error(errorMsg);
      }

      const text = await response.text();
      try {
        return JSON.parse(text);
      } catch {
        throw new Error(`Invalid JSON response from server: ${text.substring(0, 200)}`);
      }
    } catch (error) {
      console.error('[DEBUG] submitVIPRequest error:', error);
      throw error;
    }
  }

  /**
   * Save a VIP request for later approval (does NOT push to F5).
   * POST /viprequest with save_only flag.
   */
  static async createVIPDraft(request: VIPRequest): Promise<any> {
    const normalizedRequest = this.normalizeRequest(request);
    const formData = new FormData();
    formData.append('vip_name', normalizedRequest.vipName);
    formData.append('email', normalizedRequest.email);
    formData.append('ports', JSON.stringify(normalizedRequest.ports));
    formData.append('ssl', normalizedRequest.ssl.toString());
    formData.append('require_sni', normalizedRequest.requireSni ? 'true' : 'false');
    formData.append('monitor_uri', (normalizedRequest.monitorUri || '').trim());
    formData.append('monitor_recv', (normalizedRequest.monitorRecv || '').trim());
    formData.append(
      'pool_members',
      JSON.stringify(
        normalizedRequest.poolMembers.map((pm) => ({
          ip_address: pm.ipAddress,
          port: pm.port,
        }))
      )
    );
    formData.append('save_only', 'true');

    if (normalizedRequest.ssl) {
      let pfxFileToSend = normalizedRequest.pfxFile;
      if (!pfxFileToSend && normalizedRequest.pfxFileBase64) {
        pfxFileToSend = this.base64ToFile(
          normalizedRequest.pfxFileBase64,
          normalizedRequest.pfxFileName || 'certificate.pfx',
          normalizedRequest.pfxFileType || 'application/x-pkcs12'
        );
      }
      if (!pfxFileToSend) {
        throw new Error('SSL is enabled but no PFX file is available to send.');
      }
      const filename = (pfxFileToSend as File).name || normalizedRequest.pfxFileName || 'certificate.pfx';
      formData.append('pfx_file', pfxFileToSend, filename);
      formData.append('pfx_password', normalizedRequest.pfxPassword || '');
    }
    // Pass SMTP details so backend notifications use the same host/port as the frontend config
    formData.append('smtp_host', apiConfig.emailSmtpHost);
    formData.append('smtp_port', String(apiConfig.emailSmtpPort));

    try {
      const response = await fetch('/viprequest', {
        method: 'POST',
        // No auth required for draft creation
        body: formData,
      });
      if (!response.ok) {
        const text = await response.text().catch(() => '');
        let errorMsg = `Failed to store VIP request: ${response.status}`;
        try {
          const errorData = JSON.parse(text);
          errorMsg = errorData.error || errorMsg;
        } catch {
          if (text) errorMsg = text;
        }
        throw new Error(errorMsg);
      }
       const text = await response.text();
       try {
         return JSON.parse(text);
       } catch {
         throw new Error(`Invalid JSON response from server: ${text.substring(0, 200)}`);
       }
    } catch (error) {
      console.error('[DEBUG] createVIPDraft error:', error);
      throw error;
    }
  }

  static async fetchVIPRequests(): Promise<VIPRequest[]> {
    const token = this.getAdminToken();
    if (!token) throw new Error('Not authenticated. Please login first.');

    const response = await fetch('/viprequest/list', {
      headers: { Authorization: `Bearer ${token}` },
    });
    this.handleUnauthorized(response);
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Failed to fetch requests: ${response.status}`);
    }
    const data = await response.json();
    const items = data.items || [];
    // Normalize backend shape to frontend VIPRequest type
    return items.map((item: any): VIPRequest => ({
      id: item.id || item.request_id || String(Date.now()),
      requestType: item.request_type || 'new_vip',
      vipName: item.vip_name_original || item.vip_name || item.vipName || '',
      vipIP: item.vip_ip || item.assigned_ip || item.ip,
      target: item.f5_target || item.target,
      targetName: item.target_name,
      email: item.email || '',
      ports: item.ports || [],
      ssl: item.ssl_enabled || item.ssl || false,
      pfxFile: undefined,
      pfxFileBase64: undefined,
      pfxPassword: item.pfx_password || '',
      poolMembers: (item.pool_members || []).map((pm: any, idx: number) => ({
        id: pm.id || String(idx),
        ipAddress: pm.ip_address || pm.ipAddress || '',
        port: pm.port || '',
      })),
      status: (item.status as VIPRequest['status']) || 'pending',
      createdAt: item.created_at || new Date().toISOString(),
      declineReason: item.decline_reason,
      assignedIP: item.assigned_ip || item.ip,
    }));
  }

  static async approveVIPRequest(requestId: string, overrideName?: string): Promise<any> {
    const token = this.getAdminToken();
    if (!token) throw new Error('Not authenticated. Please login first.');
    const fd = new FormData();
    fd.append('request_id', requestId);
    if (overrideName && overrideName.trim()) {
      fd.append('override_vip_name', overrideName.trim());
    }
    const response = await fetch('/vipcreation', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
      },
      body: fd,
    });
    this.handleUnauthorized(response);
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      const err: Error & { code?: string; status?: number; existing?: string[] } =
        new Error(errorData.error || `VIP creation failed: ${response.status}`);
      err.code = errorData.code;
      err.status = response.status;
      err.existing = errorData.existing;
      throw err;
    }
    return response.json();
  }

  static async declineVIPRequest(requestId: string, reason: string): Promise<void> {
    const token = this.getAdminToken();
    if (!token) throw new Error('Not authenticated. Please login first.');
    const response = await fetch('/viprequest/decline', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ id: requestId, reason }),
    });
    this.handleUnauthorized(response);
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Decline failed: ${response.status}`);
    }
  }

  /**
   * Identify the caller. Returns role 'admin' when a valid F5-login token is
   * present, otherwise 'anonymous' (not logged in). Used by AuthContext on load.
   */
  static async whoami(): Promise<{ username: string; email: string; role: 'admin' | 'anonymous' }> {
    const token = this.getAdminToken();
    const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
    const response = await fetch('/me', { credentials: 'include', headers });
    if (!response.ok) {
      // Token gone server-side. Drop the WHOLE session, not just the expiry:
      // a token left in localStorage rides along on the next request, 401s,
      // and bounces the user to /admin?session_expired=1 for a session they
      // never had. TOKEN_STORE is in-memory, so every backend restart puts
      // every browser in exactly this state.
      if (response.status === 401 || response.status === 404) {
        this.clearSession();
      }
      throw new Error('Could not detect authenticated user');
    }
    const data = await response.json();
    if (!data.success) {
      throw new Error(data.error || 'Could not detect authenticated user');
    }
    if (data.role !== 'admin') {
      // Backend answered 200 "anonymous". Make sure no stale token survives.
      if (this.getAdminToken()) this.clearSession();
      return { username: '', email: '', role: 'anonymous' };
    }
    if (data.role === 'admin' && typeof data.expires_at === 'number') {
      this.setTokenExpiresAt(
        data.expires_at,
        typeof data.effective_expires_at === 'number' ? data.effective_expires_at : null
      );
    }
    return {
      username: data.username,
      email: data.email,
      role: (data.role as 'admin' | 'anonymous') || 'anonymous',
    };
  }

  static async getCurrentUser(): Promise<{ username: string; email: string }> {
    const response = await fetch('/me', { credentials: 'include' });
    if (!response.ok) {
      throw new Error('Could not detect authenticated user');
    }
    const data = await response.json();
    if (!data.success || data.role !== 'admin') {
      throw new Error(data.error || 'Could not detect authenticated user');
    }
    return { username: data.username, email: data.email };
  }

  /**
   * List existing VIPs from F5 (grouped by root name).
   * GET /f5/vips
   */
  static async listVIPs(target?: string): Promise<F5VIP[]> {
    const token = this.getAdminToken();
    const url = target ? `/f5/vips?target=${target}` : '/f5/vips';
    const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
    const response = await fetch(url, {
      headers,
      credentials: 'include',
    });
    if (response.status === 401 && token) {
      this.handleUnauthorized(response);
    }
    if (!response.ok) {
      await this.throwHttpError(response, `Failed to list VIPs: ${response.status}`);
    }
    const data = await response.json();
    return data.vips || [];
  }

  static async streamVIPs(
    onBatch: (vips: F5VIP[]) => void,
    target?: string,
    signal?: AbortSignal
  ): Promise<void> {
    const params = new URLSearchParams();
    if (target) params.set('target', target);
    const url = '/f5/vips/stream' + (params.toString() ? `?${params.toString()}` : '');
    await this.streamNdjson(
      url,
      (event) => {
        if (event.event === 'batch' && Array.isArray(event.vips)) {
          onBatch(event.vips as F5VIP[]);
        }
      },
      signal,
      'include',
      false
    );
  }

  /**
   * Add a new port (new VS + new pool + new monitor) to an existing VIP.
   * POST /f5/add-port
   */
  static async addPort(payload: {
    vip_name: string;
    vip_ip: string;
    target: string;
    port: string;
    pool_members: Array<{ ip_address: string }>;
    monitor_type?: 'tcp' | 'https';
    monitor_uri: string;
    monitor_recv: string;
    ssl_enabled?: boolean;
    clientssl_profile?: string;
  }): Promise<{
    mode?: 'vs' | 'irule';
    vs_name: string;
    pool_name: string;
    monitor_name: string;
    vip_ip: string;
    irule_name?: string;
    irule_version?: number;
  }> {
    const token = this.getAdminToken();
    if (!token) throw new Error('Not authenticated. Please login first.');
    const response = await fetch('/f5/add-port', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    this.handleUnauthorized(response);
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      const err: Error & { code?: string; status?: number } =
        new Error(errorData.error || `Failed to add port: ${response.status}`);
      err.code = errorData.code;
      err.status = response.status;
      throw err;
    }
    return response.json();
  }

  static async createAddPortRequest(payload: {
    vip_name: string;
    vip_ip: string;
    target: string;
    port: string;
    email: string;
    pool_members: Array<{ ip_address: string }>;
    monitor_type?: 'tcp' | 'https';
    monitor_uri: string;
    monitor_recv: string;
    ssl_enabled?: boolean;
    clientssl_profile?: string;
  }): Promise<{ id: string; message: string }> {
    const response = await fetch('/f5/add-port/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Failed to store add-port request: ${response.status}`);
    }
    return response.json();
  }

  /**
   * List the versioned switch iRules for an all-ports VIP and which one is active.
   * GET /f5/irule/versions
   */
  static async getIRuleVersions(
    target: string,
    vipName: string,
    vipIp: string,
  ): Promise<{ base: string; versions: IRuleVersion[]; active_version: number | null; vs_name: string | null }> {
    const token = this.getAdminToken();
    if (!token) throw new Error('Not authenticated. Please login first.');
    const params = new URLSearchParams({ target, vip_name: vipName, vip_ip: vipIp });
    const response = await fetch(`/f5/irule/versions?${params.toString()}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    this.handleUnauthorized(response);
    if (!response.ok) {
      await this.throwHttpError(response, `Failed to list iRule versions: ${response.status}`);
    }
    return response.json();
  }

  /**
   * Roll an all-ports VIP's virtual server back to a prior iRule version.
   * POST /f5/irule/rollback
   */
  static async rollbackIRule(payload: {
    vip_name: string;
    vip_ip: string;
    target: string;
    to_version: number;
  }): Promise<{ vs_name: string; active_version: number; irule_name: string }> {
    const token = this.getAdminToken();
    if (!token) throw new Error('Not authenticated. Please login first.');
    const response = await fetch('/f5/irule/rollback', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    this.handleUnauthorized(response);
    if (!response.ok) {
      await this.throwHttpError(response, `Failed to roll back iRule: ${response.status}`);
    }
    return response.json();
  }

  /**
   * Get current cert info for a given client-SSL profile.
   * GET /f5/cert-info
   */
  static async getCertInfo(target: string, profile: string): Promise<CertInfo> {
    const token = this.getAdminToken();
    const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
    const params = new URLSearchParams({ target, profile });
    const response = await fetch(`/f5/cert-info?${params.toString()}`, {
      headers,
      credentials: 'include',
    });
    if (response.status === 401 && token) {
      this.handleUnauthorized(response);
    }
    if (!response.ok) {
      await this.throwHttpError(response, `Failed to get cert info: ${response.status}`);
    }
    const data = await response.json();
    return data.info || {};
  }

  /**
   * Parse a PFX locally on the server (no upload to F5) and return cert metadata.
   * POST /f5/parse-pfx
   */
  static async parsePfx(pfxFile: File, password: string): Promise<CertInfo> {
    const token = this.getAdminToken();
    const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
    const fd = new FormData();
    fd.append('pfx_file', pfxFile, pfxFile.name);
    fd.append('pfx_password', password);
    const response = await fetch('/f5/parse-pfx', {
      method: 'POST',
      headers,
      credentials: 'include',
      body: fd,
    });
    if (response.status === 401 && token) {
      this.handleUnauthorized(response);
    }
    if (!response.ok) {
      await this.throwHttpError(response, `Failed to parse PFX: ${response.status}`);
    }
    const data = await response.json();
    return data.info || {};
  }

  /**
   * Replace cert on an existing client-SSL profile, or create a new one and attach
   * it to a chosen VS if the VIP has no profile yet.
   * POST /f5/replace-cert
   */
  static async replaceCert(params: {
    target: string;
    vip_name: string;
    pfx_file: File;
    pfx_password: string;
    mode: 'replace' | 'create';
    profile?: string;
    attach_vs?: string;
  }): Promise<{
    mode: 'replace' | 'create';
    profile: string;
    cert: string;
    key: string;
    attached_to?: string;
  }> {
    const token = this.getAdminToken();
    const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
    const fd = new FormData();
    fd.append('target', params.target);
    fd.append('vip_name', params.vip_name);
    fd.append('mode', params.mode);
    fd.append('pfx_file', params.pfx_file, params.pfx_file.name);
    fd.append('pfx_password', params.pfx_password);
    if (params.mode === 'replace' && params.profile) {
      fd.append('profile', params.profile);
    }
    if (params.mode === 'create' && params.attach_vs) {
      fd.append('attach_vs', params.attach_vs);
    }
    const response = await fetch('/f5/replace-cert', {
      method: 'POST',
      headers,
      credentials: 'include',
      body: fd,
    });
    if (response.status === 401 && token) {
      this.handleUnauthorized(response);
    }
    if (!response.ok) {
      await this.throwHttpError(response, `Failed to replace cert: ${response.status}`);
    }
    return response.json();
  }

  /**
   * List audit entries (admin only).
   * GET /audit?type=...&search=...&limit=N
   */
  static async listAudit(opts?: {
    type?: 'admin' | 'api' | 'requester';
    search?: string;
    limit?: number;
  }): Promise<AuditEntry[]> {
    const token = this.getAdminToken();
    if (!token) throw new Error('Not authenticated. Please login first.');
    const params = new URLSearchParams();
    if (opts?.type) params.set('type', opts.type);
    if (opts?.search) params.set('search', opts.search);
    if (opts?.limit) params.set('limit', String(opts.limit));
    const url = '/audit' + (params.toString() ? `?${params.toString()}` : '');
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    this.handleUnauthorized(response);
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Failed to load audit: ${response.status}`);
    }
    const data = await response.json();
    return data.entries || [];
  }

  /**
   * Revert an audit entry (admin only).
   * POST /audit/revert  body: { id }
   */
  static async revertAudit(id: string): Promise<{ action: string; undone: string[] }> {
    const token = this.getAdminToken();
    if (!token) throw new Error('Not authenticated. Please login first.');
    const response = await fetch('/audit/revert', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ id }),
    });
    this.handleUnauthorized(response);
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Failed to revert: ${response.status}`);
    }
    return response.json();
  }

  /**
   * Read-only F5 status snapshot: every VS with its pool, monitor, and member up/down.
   * GET /f5/status[?target=dmz|dc]
   */
  static async getF5Status(target?: string): Promise<F5StatusVip[]> {
    const token = this.getAdminToken();
    const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
    const url = '/f5/status' + (target ? `?target=${target}` : '');
    const response = await fetch(url, { headers, credentials: 'include' });
    if (response.status === 401 && token) {
      this.handleUnauthorized(response);
    }
    if (!response.ok) {
      await this.throwHttpError(response, `Failed to load status: ${response.status}`);
    }
    const data = await response.json();
    return data.entries || [];
  }

  static async streamF5Status(
    onBatch: (entries: F5StatusVip[]) => void,
    target?: string,
    onProgress?: (event: Record<string, unknown>) => void,
    signal?: AbortSignal
  ): Promise<void> {
    const params = new URLSearchParams();
    if (target) params.set('target', target);
    const url = '/f5/status/stream' + (params.toString() ? `?${params.toString()}` : '');
    await this.streamNdjson(
      url,
      (event) => {
        if (event.event === 'batch' && Array.isArray(event.entries)) {
          onBatch(event.entries as F5StatusVip[]);
          return;
        }
        if (event.event === 'start' || event.event === 'environment' || event.event === 'done') {
          onProgress?.(event);
        }
      },
      signal,
      'include',
      false
    );
  }

  /**
   * Transition history for a single pool member.
   * GET /f5/node-history?key=...&limit=N
   */
  static async getNodeHistory(key: string, limit = 50): Promise<NodeHistoryEntry[]> {
    const token = this.getAdminToken();
    const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
    const params = new URLSearchParams({ key, limit: String(limit) });
    const response = await fetch(`/f5/node-history?${params.toString()}`, {
      headers,
      credentials: 'include',
    });
    if (response.status === 401 && token) {
      this.handleUnauthorized(response);
    }
    if (!response.ok) {
      await this.throwHttpError(response, `Failed to load history: ${response.status}`);
    }
    const data = await response.json();
    return data.entries || [];
  }

  /**
   * Point-in-time traffic counters for a pool's members (for the flow graph).
   * GET /f5/pool/stats
   */
  static async getPoolStats(target: string, pool: string): Promise<PoolStats> {
    const token = this.getAdminToken();
    const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
    const params = new URLSearchParams({ target, pool });
    const response = await fetch(`/f5/pool/stats?${params.toString()}`, {
      headers,
      credentials: 'include',
    });
    if (response.status === 401 && token) {
      this.handleUnauthorized(response);
    }
    if (!response.ok) {
      await this.throwHttpError(response, `Failed to load pool stats: ${response.status}`);
    }
    return response.json();
  }

  static async clearVIPRequests(): Promise<void> {
    const token = this.getAdminToken();
    if (!token) throw new Error('Not authenticated. Please login first.');
    const response = await fetch('/viprequest/clear', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    this.handleUnauthorized(response);
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Failed to clear requests: ${response.status}`);
    }
  }

  /**
   * Helper to log FormData entries (for debugging).
   */
  private static logFormData(fd: FormData): void {
    try {
      const entries = (fd as any).entries?.();
      if (entries) {
        console.log('[DEBUG] FormData contents:');
        for (const [key, value] of entries) {
          if (value instanceof File) {
            console.log(`  ${key}: File(name="${value.name}", size=${value.size}, type="${value.type}")`);
          } else {
            console.log(`  ${key}: ${String(value).substring(0, 100)}`);
          }
        }
      }
    } catch (e) {
      console.log('[DEBUG] FormData logging error:', e);
    }
  }

  /**
   * Send email notification. Requires admin token.
   * POST /vipcreation/notify
   */
  static async sendEmailNotification(notification: EmailNotification): Promise<Response> {
    const token = this.getAdminToken();
    if (!token) {
      throw new Error('Not authenticated. Please login first.');
    }

    const response = await fetch(`/vipcreation/notify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({
        to: notification.to,
        subject: notification.subject,
        body: notification.body,
        smtp_host: apiConfig.emailSmtpHost,
        smtp_port: apiConfig.emailSmtpPort,
      }),
    });

    this.handleUnauthorized(response);
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Email notification failed: ${response.status}`);
    }

    return response;
  }
}
