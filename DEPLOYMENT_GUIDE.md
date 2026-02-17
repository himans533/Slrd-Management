# Deployment Guide - Employee Dashboard Fixes

## Overview
This guide provides step-by-step instructions to deploy the fixes for the employee dashboard functionality.

## Changes Summary
- Fixed task progress update endpoint (`/api/employee/tasks/{taskId}/update`)
- Fixed daily report submission endpoint (`/api/employee/daily-report`)
- Added employee daily reports retrieval endpoint (`/api/employee/daily-reports`)
- Added admin daily reports management endpoints
- Updated database schema with new `daily_task_reports` table and task progress columns

## Pre-Deployment Checklist

### Database Requirements
- PostgreSQL database with the following environment variables set:
  - `PGHOST`: Database hostname
  - `PGDATABASE`: Database name
  - `PGUSER`: Database username
  - `PGPASSWORD`: Database password
  - `PGPORT`: Database port (default: 5432)

### Environment Variables
Ensure these are configured in your hosting environment (e.g., Railway, Vercel, or other hosting provider):

```
PGHOST=your-database-host
PGDATABASE=your-database-name
PGUSER=your-database-user
PGPASSWORD=your-database-password
PGPORT=5432
ADMIN_EMAIL=your-admin-email
ADMIN_PASSWORD=your-admin-password
ADMIN_OTP=your-admin-otp
RECAPTCHA_SITE_KEY=your-recaptcha-key
RECAPTCHA_SECRET_KEY=your-recaptcha-secret
```

## Deployment Steps

### Step 1: Push Code Changes
1. Commit all changes to your Git repository:
   ```bash
   git add .
   git commit -m "Fix employee dashboard task progress and daily report endpoints"
   git push origin main
   ```

2. Or use the v0 GitHub integration to push changes directly from v0

### Step 2: Database Initialization
The database schema will be automatically initialized when the application starts. The `init_db()` function will:
1. Drop existing tables (if any)
2. Create all new tables including `daily_task_reports`
3. Add new columns to existing tables (`progress` and `notes` to tasks table)

**Note**: The initialization only happens on first startup or when explicitly triggered.

### Step 3: Deploy Application
Deploy to your hosting platform:

#### If using Railway:
1. Connect your GitHub repository to Railway
2. Push changes to the main branch
3. Railway will automatically rebuild and deploy

#### If using Vercel:
1. Connect your GitHub repository to Vercel
2. Vercel will automatically detect changes and deploy
3. Ensure environment variables are set in Vercel dashboard

#### If using other hosting:
1. Pull the latest code
2. Install Python dependencies: `pip install -r requirements.txt`
3. Restart the Flask application

### Step 4: Verify Deployment

#### Check Backend APIs
Test the new endpoints using curl or Postman:

**Test Employee Task Update:**
```bash
curl -X PUT http://localhost:5000/api/employee/tasks/1/update \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "In Progress",
    "progress": 50,
    "notes": "Half way done"
  }'
```

**Test Daily Report Submission:**
```bash
curl -X POST http://localhost:5000/api/employee/daily-report \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "task_id": 1,
    "project_id": 1,
    "report_date": "2024-01-15",
    "work_description": "Completed backend setup",
    "time_spent": 4,
    "status": "In Progress",
    "blocker": "Waiting for design review"
  }'
```

**Test Employee Daily Reports Retrieval:**
```bash
curl -X GET http://localhost:5000/api/employee/daily-reports \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Test Admin Daily Reports:**
```bash
curl -X GET http://localhost:5000/api/admin/daily-reports \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

#### Check Frontend Functionality
1. Log in as an employee
2. Navigate to Employee Dashboard
3. Test Update Task Progress:
   - Click an assigned task
   - Click "Update Progress" button
   - Fill in the form and submit
   - Verify success message and data updates

4. Test Daily Report Submission:
   - Click an assigned task
   - Click "Submit Daily Report" button
   - Fill in all required fields (especially report_date!)
   - Submit and verify success

5. Check Admin Dashboard:
   - Log in as admin
   - Navigate to Daily Reports section
   - View submitted reports with all details
   - Test filtering and approval features

## Troubleshooting

### Issue: "Missing required field: report_date" Error
**Solution**: Ensure the date field is properly filled in the form before submission. The API requires a valid date in YYYY-MM-DD format.

### Issue: Task Progress Not Updating
**Solution**: 
1. Check that the user has permission to update the task (is assigned or creator)
2. Verify the progress value is between 0-100
3. Check server logs for any database errors
4. Ensure the database has the `progress` column in the `tasks` table

### Issue: Database Connection Error
**Solution**:
1. Verify all `PGHOST`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, and `PGPORT` environment variables are set correctly
2. Test database connection manually: `psql -h $PGHOST -U $PGUSER -d $PGDATABASE`
3. Check if PostgreSQL server is running and accessible

### Issue: Daily Reports Not Showing
**Solution**:
1. Verify reports were submitted successfully (check for success message)
2. Check admin dashboard to confirm reports exist
3. Clear browser cache and reload
4. Check server logs for any errors

### Issue: 403 Forbidden on Admin Endpoints
**Solution**:
1. Verify you're logged in as admin user
2. Check that the authorization token is being sent correctly
3. Verify admin session is still valid

## Rollback Procedure

If deployment causes issues:

1. **Revert Code Changes**:
   ```bash
   git revert HEAD
   git push origin main
   ```

2. **Redeploy Previous Version**: Your hosting platform will automatically redeploy the previous stable version

3. **Database Reset** (if needed):
   - Delete the `daily_task_reports` table
   - Remove `progress` and `notes` columns from `tasks` table
   - Or restore from backup

## Performance Considerations

1. **Database Indexing**: Consider adding indexes on frequently queried columns:
   ```sql
   CREATE INDEX idx_daily_reports_user_date ON daily_task_reports(user_id, report_date);
   CREATE INDEX idx_daily_reports_project ON daily_task_reports(project_id);
   ```

2. **Query Optimization**: The admin daily reports endpoint with many filters may need optimization for large datasets. Consider pagination.

3. **Caching**: For frequently accessed data, implement caching to reduce database load.

## Post-Deployment Tasks

1. **Monitor Logs**: Watch application and database logs for errors
2. **User Communication**: Notify users about the new features
3. **Training**: Provide guidance on how to use the new progress update and daily report features
4. **Feedback Collection**: Gather user feedback and iterate on the implementation

## Support

If you encounter any issues during deployment:
1. Check the application logs for error messages
2. Verify all environment variables are correctly set
3. Review this guide for common troubleshooting steps
4. Contact the development team if issues persist

## Additional Resources

- PostgreSQL Documentation: https://www.postgresql.org/docs/
- Flask Documentation: https://flask.palletsprojects.com/
- Railway Deployment: https://railway.app/docs
- Vercel Deployment: https://vercel.com/docs
