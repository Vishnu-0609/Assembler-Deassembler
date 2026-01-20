# 🔧 Quick Fix for Railway Error

## The Problem:
`uvicorn: command not found` - Railway isn't installing dependencies

## ✅ Solution:

### Step 1: Push Updated Files
I've created a root `requirements.txt` file. Push it:

```bash
git add .
git commit -m "Add root requirements.txt for Railway"
git push
```

### Step 2: Configure Railway Manually (Recommended)

1. **Go to Railway Dashboard** → Your Project → Your Service
2. **Click "Settings"** tab
3. **Scroll to "Build & Deploy"** section
4. **Set Build Command**:
   ```
   python -m pip install --upgrade pip && python -m pip install -r backend/requirements.txt
   ```
5. **Set Start Command**:
   ```
   cd backend && python -m uvicorn main:app --host 0.0.0.0 --port $PORT
   ```
6. **Click "Save"**
7. **Railway will redeploy automatically**

### Step 3: Verify

Check the **Deployments** tab. You should see:
- ✅ Build succeeds
- ✅ Dependencies installed
- ✅ App starts successfully

## 🎯 Alternative: Use Root requirements.txt

Railway auto-detects `requirements.txt` in the root folder. I've created one for you.

Just push and Railway should work:
```bash
git add requirements.txt
git commit -m "Add root requirements.txt"
git push
```

## 📋 Files Created:

- ✅ `requirements.txt` (root) - For Railway auto-detection
- ✅ `nixpacks.toml` - Build configuration
- ✅ `start.sh` - Startup script
- ✅ `railway.toml` - Railway config

**Push all these files and Railway should work!** 🚀
