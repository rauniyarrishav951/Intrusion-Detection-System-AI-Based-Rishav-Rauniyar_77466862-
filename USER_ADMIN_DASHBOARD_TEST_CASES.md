# IDS Flask Project Test Cases

## Overview
This document describes manual test cases for the `user_dashboard` and `admin_panel` features in the IDS Flask project. The cases verify authentication, authorization, page rendering, and key dashboard content.

---

## Preconditions
- The Flask app is running and connected to `ids.db`.
- Test users exist in the database:
  - `standard user`: role = `user`
  - `admin user`: role = `admin`
- The `ids.db` contains at least one active model in `model_metrics` and sample traffic/events, or the dashboard gracefully handles empty data sets.
- Browser or API client available.

---

## Test Case 1: User Dashboard Access and Content

### ID
TC-UD-01

### Objective
Verify that a logged-in standard user can access the user dashboard and see the expected IDS content.

### Preconditions
- A valid standard user account exists.
- The user is not an admin.

### Test Steps
1. Open the application login page (`/login`).
2. Enter valid standard user credentials and submit.
3. Confirm successful login redirect to `/user_dashboard`.
4. Verify the page title contains `IDS Dashboard - User Panel`.
5. Verify the logged-in username appears in the page header.
6. Confirm the user dashboard contains the following sections or content:
   - Detection events summary or list.
   - Model performance metrics section.
   - Activity logs section.
   - Network traffic list or chart section.
   - Dataset summary or preview section.
7. Click the `Logout` button and verify redirect to the landing or login page.

### Expected Result
- The login successfully authenticates the user.
- `/user_dashboard` loads without error.
- Username is visible in the dashboard header.
- Detection events, traffic, logs, and metrics are displayed.
- User is able to logout and return to a public page.

### Notes
- If no data is available, the dashboard should still render and display empty or default content gracefully.
- The dashboard route is protected by `@web_login_required`.

---

## Test Case 2: User Dashboard Authorization

### ID
TC-UD-02

### Objective
Verify that unauthorized users cannot access the user dashboard and are redirected to login.

### Preconditions
- User is not authenticated.

### Test Steps
1. Open the browser and navigate directly to `/user_dashboard`.
2. Confirm the app redirects to `/login`.
3. Attempt the same with `/ids` or `/dashboard`.
4. Confirm each route also redirects to `/login`.

### Expected Result
- Unauthenticated access to all dashboard routes is blocked.
- The app redirects to the login page.

### Notes
- These routes are protected by the `web_login_required` decorator.

---

## Test Case 3: Admin Panel Access and Content

### ID
TC-AP-01

### Objective
Verify that a logged-in admin user can access the admin panel and view admin-only data.

### Preconditions
- A valid admin user account exists.
- The admin has at least one user record and system configuration entries.

### Test Steps
1. Open the application login page (`/login`).
2. Enter valid admin credentials and submit.
3. Confirm successful login redirect to `/admin`.
4. Verify the page title contains `Admin Panel - IDS System`.
5. Verify the admin username appears in the page header.
6. Confirm the admin panel contains the following sections or content:
   - User management table with usernames and roles.
   - Admin audit trail or action log section.
   - System configuration panel.
   - Dashboard summary content.
7. Verify that the admin can navigate to the `Logout` link and sign out.

### Expected Result
- Admin login succeeds and redirects to `/admin`.
- The admin panel renders without error.
- Admin-specific content appears, including users, audit trail, and configs.
- Logout works and returns the user to the public page.

### Notes
- The admin panel is protected by the `admin_required` decorator.

---

## Test Case 4: Admin Authorization Enforcement

### ID
TC-AP-02

### Objective
Verify that non-admin users cannot access the admin panel.

### Preconditions
- A valid standard user account exists.
- The user is authenticated but not an admin.

### Test Steps
1. Login as a standard user.
2. Navigate directly to `/admin`.
3. Confirm the app displays a flash message `Admin access required` or equivalent.
4. Confirm the user is redirected to `/user_dashboard`.

### Expected Result
- The non-admin user is blocked from `/admin`.
- A redirect occurs to the standard user dashboard.
- The admin access message is shown.

### Notes
- This tests the `admin_required` guard logic.

---

## Test Case 5: Admin API Endpoints from Admin Panel

### ID
TC-AP-03

### Objective
Validate that the admin panel backend endpoints return expected JSON data for user management and audit trail.

### Preconditions
- Admin user is logged in.

### Test Steps
1. Login as admin.
2. Request `/admin/users` via browser or API client.
3. Verify response is JSON containing the list of users.
4. Request `/admin/audit-trail` and confirm it returns JSON audit records.
5. Request `/admin/config` and confirm it returns JSON config values.

### Expected Result
- JSON responses are returned successfully with status 200.
- User list, audit trail, and config values are present.

### Notes
- These endpoints support admin panel behavior and should only be accessible by admin users.

---

## Test Data Setup Recommendation
- Create a standard user named `testuser` with role `user`.
- Create an admin user named `adminuser` with role `admin`.
- Insert at least one `model_metrics` row with `is_active = 1`.
- Insert sample `network_traffic`, `detection_events`, and `activity_logs` records if needed.

---

## Success Criteria
- All page routes render successfully for permitted users.
- Unauthorized access is blocked and redirected appropriately.
- Dashboard and admin interfaces display the expected sections and data.
- Logout ends the session and clears access to protected pages.
