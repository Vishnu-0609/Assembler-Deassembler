# 🔧 Railway Deployment Fix

## Problem:
`uvicorn: command not found` error on Railway

## Solution:
I've created multiple configuration files to fix this:

### Files Created/Updated:
1. ✅ `requirements.txt` (root) - Railway auto-detects this
2. ✅ `nixpacks.toml` - Explicit build configuration
3. ✅ `start.sh` - Startup script
4. ✅ Updated `Procfile` - Uses the startup script
5. ✅ Updated `railway.json` - Correct start command

## 🔄 What to Do:

### Option 1: Use Root requirements.txt (Easiest)

Railway will auto-detect `requirements.txt` in the root folder.

1. **Push the updated files**:
   ```bash
   git add .
   git commit -m "Fix Railway deployment - add root requirements.txt"
   git push
   ```

2. **Railway will automatically redeploy** with the new configuration

### Option 2: Configure Build Command in Railway Dashboard

1. Go to your Railway project
2. Click on your service
3. Go to **Settings** → **Build**
4. Set **Build Command**:
   ```
   pip install --upgrade pip && pip install -r backend/requirements.txt
   ```
5. Set **Start Command**:
   ```
   cd backend && python -m uvicorn main:app --host 0.0.0.0 --port $PORT
   ```

### Option 3: Use Nixpacks Configuration

The `nixpacks.toml` file should automatically configure Railway to:
- Install Python 3.10
- Install dependencies from `backend/requirements.txt`
- Start the app correctly

## ✅ Verification:

After pushing, check Railway logs. You should see:
- ✅ `Installing dependencies...`
- ✅ `Successfully installed fastapi uvicorn keystone-engine capstone`
- ✅ `Application startup complete`

## 🆘 If Still Not Working:

1. **Check Railway logs** for build errors
2. **Try setting environment variable** in Railway:
   - `PYTHONPATH=/app/backend`
3. **Use Railway's Python template**:
   - Delete current service
   - Create new service → Python template
   - Point to your repo
   - Set start command manually

## 📝 Quick Fix Commands:

```bash
# Push updated files
git add .
git commit -m "Fix Railway deployment"
git push

# Railway will auto-redeploy
```

The root `requirements.txt` should fix the issue! 🚀
