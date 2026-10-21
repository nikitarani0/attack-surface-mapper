# Attack Surface Report — tesla.com

- **Scan ID:** 9
- **Started:** 2026-10-21T01:54:58.879304+00:00
- **Finished:** 2026-10-21T01:55:10.699547+00:00
- **Generated:** 2026-10-21T05:12:28.747294+00:00

## Summary

| Asset type | Count |
|---|---|
| Subdomains discovered | 189 |
| Live web hosts | 145 |
| Open services | 0 |
| Cloud assets | 2 |
| Endpoints | 2646 |
| Secrets flagged | 0 |
| **Total findings** | **143** |

**Findings by severity:** 🟡 Medium: 89 · 🔵 Low: 54

## Findings

### 🟡 [MEDIUM] Potential SSRF vector (param: next)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /ROOT/node_modules/next/dist/compiled/process/ exposes 'next' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /about?redirect=no exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /about?redirect=no exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /about?redirect=no exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: callback)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /account/auth/callback exposes 'callback' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: callback)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /account/auth/callback exposes 'callback' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: callback)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /account/auth/callback exposes 'callback' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /api/user/auth/redirect exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: callback)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /auth/callback exposes 'callback' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: proxy)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /cors/proxy exposes 'proxy' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: callback)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /employee/auth/callback exposes 'callback' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: destination)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /gtag/destination exposes 'destination' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: destination)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /gtag/destination exposes 'destination' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: destination)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /gtag/destination exposes 'destination' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /impressum?redirect=no exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /impressum?redirect=no exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /impressum?redirect=no exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /legal/privacy?redirect=no exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /legal/privacy?redirect=no exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /legal?redirect=no exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /legal?redirect=no exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /legal?redirect=no exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /logout?redirect= exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: callback)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /oauth2/callback exposes 'callback' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: callback)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /oauth2/v3/authorize/callback/ou/ exposes 'callback' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: callback)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /oauth2/v3/authorize/callback/ou/ exposes 'callback' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: callback)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /oauth2/v3/authorize/callback/ou/ exposes 'callback' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: callback)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /oauth2/v3/authorize/callback/ou/ exposes 'callback' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: callback)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /oauth2/v3/authorize/callback/ou/ exposes 'callback' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /orders?redirect=no&signIn=true exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: path)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /path/to/certs/grafana-host-key.pem exposes 'path' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: path)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /path/to/certs/grafana-host.pem exposes 'path' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: path)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /path/to/idp-metadata exposes 'path' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: proxy)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /proxy exposes 'proxy' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: load)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /recaptcha/api.js?onload= exposes 'load' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: load)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /recaptcha/api.js?onload= exposes 'load' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: load)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /recaptcha/api.js?onload= exposes 'load' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: load)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /recaptcha/api.js?onload= exposes 'load' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: load)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /recaptcha/api.js?onload= exposes 'load' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: load)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /recaptcha/enterprise.js?onload= exposes 'load' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: load)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /recaptcha/enterprise.js?onload= exposes 'load' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: load)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /recaptcha/enterprise.js?onload= exposes 'load' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: load)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /recaptcha/enterprise.js?onload= exposes 'load' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: load)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /recaptcha/enterprise.js?onload= exposes 'load' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /redirect/addApplications exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /teslaaccount/owner-xp/auth/logout?redirect=true exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /teslaaccount/owner-xp/auth/logout?redirect=true exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: redirect)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /teslaaccount/owner-xp/auth/logout?redirect=true exposes 'redirect' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: callback)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint /web/msg/error/login/callback exposes 'callback' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/controlled-components exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/controlled-components exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/controlled-components exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/controlled-components exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/react-devtools exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/react-devtools exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/react-devtools exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/react-devtools exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/react-devtools-faq exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/react-devtools-faq exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/react-devtools-faq exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/react-devtools-faq exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/rules-of-hooks exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/rules-of-hooks exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/rules-of-hooks exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/rules-of-hooks exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/strict-mode-find-node exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/strict-mode-find-node exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/strict-mode-find-node exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/strict-mode-find-node exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/strict-mode-string-ref exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/strict-mode-string-ref exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/strict-mode-string-ref exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/strict-mode-string-ref exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/strict-mode-string-ref exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/strict-mode-string-ref exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/strict-mode-string-ref exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/strict-mode-string-ref exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/unsafe-component-lifecycles exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/unsafe-component-lifecycles exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/unsafe-component-lifecycles exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Potential SSRF vector (param: link)

- **Category:** ssrf-candidate
- **Correlation:** `ssrf_imds_candidate`
- **Evidence:** Endpoint https://reactjs.org/link/unsafe-component-lifecycles exposes 'link' param — manual test for SSRF→IMDS

### 🟡 [MEDIUM] Sensitive path exposed: 'admin'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /admin (found via https://livestream.tesla.com/bundle.js)

### 🟡 [MEDIUM] Sensitive path exposed: 'admin'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /admin-ticket/ (found via https://bjm.tesla.com/assets/index-CKxlHSU-.js)

### 🟡 [MEDIUM] Sensitive path exposed: 'admin'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /admin/api/uxversion (found via https://myapps.microsoft.com/bundle/low-change-freq-vendors.2d89db9a.js)

### 🟡 [MEDIUM] Sensitive path exposed: 'admin'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /administrativeUnits/ (found via https://myapps.microsoft.com/bundle/main.bb62e4c4.js)

### 🟡 [MEDIUM] Sensitive path exposed: '.git'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://api.githubcopilot.com (found via https://extgithub.tesla.com/login)

### 🟡 [MEDIUM] Sensitive path exposed: 'admin'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://cloudinary.com/wp-admin/admin-ajax.php (found via https://cloudinary.com)

### 🟡 [MEDIUM] Sensitive path exposed: 'admin'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://docs.servicenow.com/bundle/vancouver-platform-administration/page/administer/roles/task/t_AddARoleToAnExistingRole.html (found via https://edge-teleport.tesla.com/web/app/app.js)

### 🟡 [MEDIUM] Sensitive path exposed: 'admin'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://echoadmin-api-stg.tesla.com (found via https://echo-internal.tesla.com/bundle/main.412ab6bf.js)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /.well-known/openid-configuration (found via https://billing.tesla.com/_next/static/chunks/pages/_app-bd562d36fa6bc2282ca5.js)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /.well-known/openid-configuration (found via https://ok1static.oktacdn.com/assets/js/sdk/okta-signin-widget/1.7.0/js/okta-sign-in.min.js)

### 🔵 [LOW] Sensitive path exposed: 'test'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** //player.polyv.net/resp/vod-player/latest/player.js (found via https://echo-internal.tesla.com/bundle/vendors.c02a99a9.js)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /account/api/configs (found via https://edr.tesla.com/app.ae8b9e9bfaa34d1012b4.js)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /account/api/configs (found via https://static-assets-teslaaccount.tesla.com/main.js)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /account/api/configs (found via https://static-assets-profile-settings.tesla.com/main.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /api/device (found via https://bjm.tesla.com/assets/index-CKxlHSU-.js)

### 🔵 [LOW] Sensitive path exposed: 'internal'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /api/internal/su/orgs (found via https://ok1static.oktacdn.com/assets/js/sdk/okta-signin-widget/1.7.0/js/okta-sign-in.min.js)

### 🔵 [LOW] Sensitive path exposed: 'internal'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /api/internalparkingpermit (found via https://bjm.tesla.com/assets/index-CKxlHSU-.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /authenticate_web_device (found via https://edge-teleport.tesla.com/web/app/app.js)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /config-c7hxwwp3.js (found via https://auth.tesla.com)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /config-c7hxwwp3.js (found via https://auth.prd.euw1.vn.cloud.tesla.com)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /config-c7hxwwp3.js (found via https://fleet-auth.prd.vn.cloud.tesla.com)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /config-zq2pj5ur.js (found via https://auth-stage.tesla.com)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /config-zq2pj5ur.js (found via https://auth.eng.euw1.vn.cloud.tesla.com)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /config/v1/Centro/1.0.0.0 (found via https://myapps.microsoft.com/bundle/low-change-freq-vendors.2d89db9a.js)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /configuration/ (found via https://d2c7xlmseob604.cloudfront.net/tracker.min.js)

### 🔵 [LOW] Sensitive path exposed: 'debug'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /debug/bootstrap?id= (found via https://www.googletagmanager.com/gtag/js)

### 🔵 [LOW] Sensitive path exposed: 'debug'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /debug/bootstrap?id= (found via https://www.googletagmanager.com/gtag/js?id=GT-WVCFBP2H)

### 🔵 [LOW] Sensitive path exposed: 'debug'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /debug/bootstrap?id= (found via https://www.googletagmanager.com/gtag/js?id=AW-16529134460)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /developers (found via https://cloudinary.com)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /device-list (found via https://myapps.microsoft.com/bundle/main.bb62e4c4.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /devicecode (found via https://myapps.microsoft.com/bundle/azure.880648d5.js)

### 🔵 [LOW] Sensitive path exposed: 'metrics'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /metrics (found via https://cdn-4.convertexperiments.com/v1/js/10042338-10042940.js?environment=production)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /solutions/developers (found via https://cloudinary.com/wp-content/themes/cld-2021/assets/js/utm-script.js)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /static/js/config/loadenv.1.0.js (found via https://mfa-reset.tesla.com)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /ui-config.js (found via https://dashcam.tesla.com)

### 🔵 [LOW] Sensitive path exposed: 'test'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /v1/enterprise/accessgraph/graph/tester/teleport/role/v1 (found via https://edge-teleport.tesla.com/web/app/app.js)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /v1/enterprise/pluginconfig/aws-ic/preview/accounts-with-permission-sets (found via https://edge-teleport.tesla.com/web/app/app.js)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** /web/config.js (found via https://edge-teleport.tesla.com/web)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://auth.tesla.com/oauth2/v1/.well-known/openid-configuration (found via https://mfa-reset.tesla.com/static/js/config/loadenv.1.0.js)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://cdn-4.convertexperiments.com/api/v1/config-js (found via https://cdn-4.convertexperiments.com/v1/js/10042338-10042940.js?environment=production)

### 🔵 [LOW] Sensitive path exposed: 'debug'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://cdn.debugbear.com/EHCenyitCAgM.js (found via https://cloudinary.com)

### 🔵 [LOW] Sensitive path exposed: 'config'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://config.edge.skype.com (found via https://myapps.microsoft.com/bundle/main.bb62e4c4.js)

### 🔵 [LOW] Sensitive path exposed: 'debug'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://data.debugbear.com (found via https://cdn.debugbear.com/EHCenyitCAgM.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://developer.mozilla.org/en-US/docs/DOM/MutationObserver (found via https://d2c7xlmseob604.cloudfront.net/tracker.min.js)

### 🔵 [LOW] Sensitive path exposed: 'test'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://df-entra.onecloud.azure-test.net/ (found via https://myapps.microsoft.com/bundle/main.bb62e4c4.js)

### 🔵 [LOW] Sensitive path exposed: 'internal'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://echo-internal-api-stg.tesla.com (found via https://echo-internal.tesla.com/bundle/main.412ab6bf.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://proxysvc-referral-dev.teslamotors.com (found via https://edr.tesla.com/app.ae8b9e9bfaa34d1012b4.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://proxysvc-referral-dev.teslamotors.com (found via https://static-assets-teslaaccount.tesla.com/main.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://proxysvc-referral-dev.teslamotors.com (found via https://static-assets-profile-settings.tesla.com/main.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://react.dev/errors/ (found via https://accounts.tesla.com/_next/static/chunks/main-c4b7a1c2336351ca.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://react.dev/errors/ (found via https://auth.tesla.com/assets/index-050M0ghb.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://react.dev/errors/ (found via https://auth.prd.euw1.vn.cloud.tesla.com/assets/index-050M0ghb.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://react.dev/errors/ (found via https://auth-stage.tesla.com/assets/index-DzyN9h6N.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://react.dev/errors/ (found via https://auth.eng.euw1.vn.cloud.tesla.com/assets/index-DzyN9h6N.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://react.dev/errors/ (found via https://esign.tesla.com/_next/static/chunks/37n2y244i6xgf.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://react.dev/errors/ (found via https://esign.tesla.com/_next/static/chunks/0d-e51sawr2y8.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://react.dev/errors/ (found via https://fleet-auth.prd.vn.cloud.tesla.com/assets/index-050M0ghb.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://reactjs.org/link/react-devtools (found via https://unpkg.com/react-dom@18.2.0/umd/react-dom.development.js)

### 🔵 [LOW] Sensitive path exposed: 'dev'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://res-2-dev.cdn.officeppe.net (found via https://myapps.microsoft.com/bundle/low-change-freq-vendors.2d89db9a.js)

### 🔵 [LOW] Sensitive path exposed: 'staging'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://tesla-ui-commerce-staging.stg.ep.tesla.services (found via https://edr.tesla.com/app.ae8b9e9bfaa34d1012b4.js)

### 🔵 [LOW] Sensitive path exposed: 'staging'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://tesla-ui-commerce-staging.stg.ep.tesla.services (found via https://static-assets-teslaaccount.tesla.com/main.js)

### 🔵 [LOW] Sensitive path exposed: 'staging'

- **Category:** sensitive-path
- **Correlation:** `sensitive_path_exposure`
- **Evidence:** https://tesla-ui-commerce-staging.stg.ep.tesla.services (found via https://static-assets-profile-settings.tesla.com/main.js)

## Appendix — Recon Data

### Cloud Assets

| Identifier | Provider | Type | Public | Takeover? |
|---|---|---|---|---|
| tesla-hermes-snapshot-motors-eng.s3.eng.na.vn.cloud.tesla.com | aws | aws-s3 | no | no |
| tesla-hermes-snapshot-motors.s3.prd.na.vn.cloud.tesla.com | aws | aws-s3 | no | no |

### Live Hosts (145 total, showing up to 50)

| URL | Status | Server | Tech |
|---|---|---|---|
| http://inventory-assets.tesla.com | 204 | AkamaiGHost |  |
| http://va-ap-deploy.tesla.com | 403 | Varnish |  |
| https://accounts.tesla.com/oauth2/auth-login?redirect_url_path=https://auth.tesla.com/oauth2/v1/authorize?response_type%3Dcode%26client_id%3Daccounts%26redirect_uri%3Dhttps%253A%252F%252Faccounts.tesla.com%252Foauth2%252Fcallback%26scope%3Doffline_access%2Buser%2Bprofile%2Bou_code%2Bemail%26locale%3Den-US&callback_url_path=https://accounts.tesla.com//account-settings/personal-information | 200 |  |  |
| https://akamai-apigateway-captive-stg.tesla.com | 403 | AkamaiGHost |  |
| https://akamai-apigateway-deliveryopsapi.tesla.com | 503 | AkamaiGHost |  |
| https://akamai-apigateway-fourthline-prd.tesla.com | 403 |  |  |
| https://akamai-apigateway-hire.tesla.com | 503 | AkamaiGHost |  |
| https://akamai-apigateway-inventorytxnextapi.tesla.com | 503 | AkamaiGHost |  |
| https://akamai-apigateway-lkchat-apac.tesla.com | 200 |  |  |
| https://akamai-apigateway-lkchat.tesla.com | 200 |  |  |
| https://akamai-apigateway-logisticsratesapi.tesla.com | 503 | AkamaiGHost |  |
| https://akamai-apigateway-materials.tesla.com | 503 | AkamaiGHost |  |
| https://akamai-apigateway-mfs-supplier-uat.tesla.com | 503 |  |  |
| https://akamai-apigateway-stg-packaging2.tesla.com | 503 |  |  |
| https://akamai-apigateway-stg-procuretopayapi.tesla.com | 503 |  |  |
| https://akamai-apigateway-stg-shipmentplanningapi.tesla.com | 503 |  |  |
| https://akamai-apigateway-stg-warp3pl.tesla.com | 503 |  |  |
| https://akamai-apigateway-stg-warpdashboardapi.tesla.com | 401 |  |  |
| https://akamai-apigateway-stg-warpedi.tesla.com | 503 |  |  |
| https://akamai-apigateway-stg-warptqpapi.tesla.com | 401 |  |  |
| https://akamai-apigateway-uat-materials.tesla.com | 503 |  |  |
| https://akamai-apigateway-vehicleextinfogw-prdsvc-st.tesla.com | 403 | AkamaiGHost |  |
| https://akamai-apigateway-vfx-stg.tesla.com | 503 |  |  |
| https://akamai-apigateway-warpdashboardapi.tesla.com | 503 | AkamaiGHost |  |
| https://akamai-apigateway-warptmsapiserver-upgrade.tesla.com | 503 | AkamaiGHost |  |
| https://ams13-gpgw1.tesla.com/global-protect/login.esp | 404 |  |  |
| https://api-firebolt-dev.tesla.com | 403 | AkamaiGHost |  |
| https://api-firebolt-stage.tesla.com | 403 | AkamaiGHost |  |
| https://apigateway-eagle-eye.tesla.com | 503 |  |  |
| https://apigateway-esca-service.tesla.com | 503 | AkamaiGHost |  |
| https://apigateway-nva-cht-az.tesla.com | 401 |  |  |
| https://apigateway-track-api.tesla.com | 503 |  |  |
| https://apigateway-volo-robox-bff.tesla.com | 401 |  |  |
| https://apmv3-cdn-go.tesla.com | 200 | Varnish |  |
| https://assets-ir.tesla.com | 403 | MinIO Enterprise |  |
| https://assets-tcl.tesla.com | 403 | Varnish |  |
| https://atom-na.tesla.com | 200 |  |  |
| https://auth-stage.tesla.com | 200 | envoy |  |
| https://auth-stage.teslamotors.com/ | 400 | AkamaiNetStorage |  |
| https://auth.eng.euw1.vn.cloud.tesla.com | 200 | envoy |  |
| https://auth.prd.euw1.vn.cloud.tesla.com | 200 | envoy |  |
| https://auth.tesla.com | 200 | envoy |  |
| https://bettertime-stage.tesla.com | 403 | AkamaiGHost |  |
| https://bettertime.tesla.com | 403 | AkamaiGHost |  |
| https://billing.tesla.com | 200 |  |  |
| https://bjm.tesla.com | 200 |  |  |
| https://botmesh-stg.tesla.com | 404 |  |  |
| https://botmesh.tesla.com | 404 |  |  |
| https://business-onboarding-ui.tesla.com | 200 |  |  |
| https://business.tesla.com | 200 |  |  |
