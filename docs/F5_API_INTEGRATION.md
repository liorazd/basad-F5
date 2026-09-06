# F5 REST API Integration Guide

This document describes how the F5 VIP Request Portal integrates with the official F5 REST API.

## Authentication

### Endpoint
```
POST https://{F5_MANAGEMENT_IP}/mgmt/shared/authn/login
```

### Request
```json
{
  "username": "admin",
  "password": "password",
  "loginProviderName": "tmos"
}
```

### Response
Returns a JSON object containing:
- `token`: Authentication token to use for subsequent API calls
- `tokenId`: Token identifier
- `name`: Token name
- `timeout`: Token timeout in seconds (default: 1200)

**Example:**
```json
{
  "token": "VUT2YR667OICEHAEKWBGWOJ3HF",
  "name": "VUT2YR667OICEHAEKWBGWOJ3HF",
  "timeout": 1200,
  ...
}
```

### Storage
The F5 auth token is held **server-side only**, mapped against the opaque portal
token in `TOKEN_STORE`. The browser never sees the F5 token — it stores only the
portal token (`localStorage.admin_token`) and sends it as
`Authorization: Bearer <portal_token>`. The backend then attaches the matching
`X-F5-Auth-Token` to each F5 call.

---

## Virtual Servers (VIPs)

### Get All VIPs

**Endpoint**
```
GET https://{F5_MANAGEMENT_IP}/mgmt/tm/ltm/virtual
```

**Headers**
```
Content-Type: application/json
X-F5-Auth-Token: {token}
```

**Response**
Returns a JSON object with an `items` array containing virtual server objects:

```json
{
  "kind": "tm:ltm:virtual:virtualcollectionstate",
  "selfLink": "https://localhost/mgmt/tm/ltm/virtual?ver=15.1.0",
  "items": [
    {
      "kind": "tm:ltm:virtual:virtualhandlerstate",
      "name": "vip_example",
      "destination": "10.1.1.100:80",
      "ipAddress": "10.1.1.100",
      "mask": "255.255.255.255",
      "pool": "/Common/pool_example",
      ...
    }
  ]
}
```

### Create a VIP

**Endpoint**
```
POST https://{F5_MANAGEMENT_IP}/mgmt/tm/ltm/virtual
```

**Headers**
```
Content-Type: application/json
X-F5-Auth-Token: {token}
```

**Request Body**
```json
{
  "name": "vip_name",
  "destination": "10.1.1.100:443",
  "mask": "255.255.255.255",
  "ipAddress": "10.1.1.100",
  "ipProtocol": "tcp",
  "pool": "/Common/pool_name",
  "profiles": ["/Common/http", "/Common/https"]
}
```

**Response**
Returns the created virtual server object with full details.

---

## Pool Management

### Create a Pool

**Endpoint**
```
POST https://{F5_MANAGEMENT_IP}/mgmt/tm/ltm/pool
```

**Headers**
```
Content-Type: application/json
X-F5-Auth-Token: {token}
```

**Request Body**
```json
{
  "name": "pool_name",
  "members": [
    {
      "name": "192.168.1.10:8080",
      "address": "192.168.1.10"
    }
  ]
}
```

---

## Error Handling

### Common Error Responses

**401 Unauthorized**
- Token is invalid or expired
- Clear stored token and redirect to login

**403 Forbidden**
- User does not have permission for the requested operation

**400 Bad Request**
- Invalid request payload or parameters

---

## References

- [F5 Authentication Documentation](https://clouddocs.f5.com/api/icontrol-soap/Authentication_with_the_F5_REST_API.html)
- [F5 Virtual Server API Reference](https://clouddocs.f5.com/api/icontrol-rest/APIRef_ltm_virtual.html)
- [F5 iControl REST Documentation](https://clouddocs.f5.com/api/icontrol-rest/index.html)

---

## Implementation Notes

### Session persistence
- The browser caches only the opaque portal token (`localStorage.admin_token`).
- It is cleared on logout or when a 401 is encountered.
- Users remain logged in across page reloads until the portal token expires.

### Token-based Authorization
- All F5 API calls use the `X-F5-Auth-Token` header (not `Authorization` header)
- This is the F5-specific authentication method for REST API calls

### CORS Considerations
- Browser requests to F5 API may require CORS configuration on F5
- Consider using a backend proxy if CORS is not available on F5
