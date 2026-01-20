# Deployment Guide for BroItsJustAssembly

This guide covers deploying your assembler/disassembler website to various platforms.

## ⚠️ Important Note

**Keystone and Capstone are native libraries** that require compilation. Some platforms may have limitations:
- **Vercel**: May have issues with native dependencies
- **Railway/Render**: Better support for native libraries
- **PythonAnywhere**: Good for Python apps but limited free tier

## Option 1: Deploy to Railway (Recommended)

Railway has excellent support for Python apps with native dependencies.

### Steps:

1. **Install Railway CLI** (optional, or use web interface):
   ```bash
   npm i -g @railway/cli
   ```

2. **Create a `Procfile`** (already created):
   ```
   web: cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT
   ```

3. **Create `railway.json`** (already created):
   ```json
   {
     "$schema": "https://railway.app/railway.schema.json",
     "build": {
       "builder": "NIXPACKS"
     },
     "deploy": {
       "startCommand": "cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT",
       "restartPolicyType": "ON_FAILURE",
       "restartPolicyMaxRetries": 10
     }
   }
   ```

4. **Deploy**:
   - Go to [railway.app](https://railway.app)
   - Sign up/login with GitHub
   - Click "New Project" → "Deploy from GitHub repo"
   - Select your repository
   - Railway will auto-detect Python and install dependencies
   - Add environment variable: `PORT` (Railway sets this automatically)

5. **Update Frontend**:
   - Railway will give you a URL like `https://your-app.railway.app`
   - Update `frontend/index.html` API calls if needed (they should work as-is)

## Option 2: Deploy to Render

### Steps:

1. **Create `render.yaml`** (already created):
   ```yaml
   services:
     - type: web
       name: assembler-backend
       env: python
       buildCommand: pip install -r backend/requirements.txt
       startCommand: cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT
       envVars:
         - key: PORT
           value: 8000
   ```

2. **Deploy**:
   - Go to [render.com](https://render.com)
   - Sign up/login
   - Click "New" → "Web Service"
   - Connect your GitHub repository
   - Render will auto-detect settings
   - Build command: `pip install -r backend/requirements.txt`
   - Start command: `cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT`

## Option 3: Deploy to Vercel

⚠️ **Warning**: Vercel may have issues with native libraries (keystone-engine, capstone).

### Steps:

1. **Install Vercel CLI**:
   ```bash
   npm i -g vercel
   ```

2. **Update `vercel.json`** (already created):
   The configuration routes API calls to Python functions.

3. **Deploy**:
   ```bash
   vercel login
   vercel
   ```

4. **If deployment fails** due to native libraries:
   - Try using Railway or Render instead
   - Or use Vercel with Docker (more complex)

## Option 4: Deploy to PythonAnywhere

### Steps:

1. **Sign up** at [pythonanywhere.com](https://www.pythonanywhere.com)

2. **Upload files**:
   - Use the Files tab to upload your project
   - Or use Git: `git clone https://github.com/yourusername/yourrepo.git`

3. **Set up virtual environment**:
   ```bash
   mkvirtualenv assembler --python=python3.10
   pip install -r backend/requirements.txt
   ```

4. **Create web app**:
   - Go to Web tab
   - Click "Add a new web app"
   - Choose Flask (we'll modify it)
   - Set source code to `/home/yourusername/Assembler/backend/main.py`

5. **Configure WSGI**:
   Edit the WSGI file to:
   ```python
   import sys
   sys.path.insert(0, '/home/yourusername/Assembler/backend')
   from main import app
   application = app
   ```

6. **Reload** the web app

## Option 5: Deploy to Heroku

### Steps:

1. **Create `Procfile`** (already created):
   ```
   web: cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT
   ```

2. **Create `runtime.txt`**:
   ```
   python-3.10.12
   ```

3. **Install Heroku CLI**:
   ```bash
   # Windows: Download from heroku.com
   # Or use: npm install -g heroku
   ```

4. **Deploy**:
   ```bash
   heroku login
   heroku create your-app-name
   git push heroku main
   ```

## Quick Setup Commands

### For Railway:
```bash
# Install Railway CLI
npm i -g @railway/cli

# Login
railway login

# Initialize
railway init

# Deploy
railway up
```

### For Render:
Just connect your GitHub repo on render.com - it's that simple!

### For Vercel:
```bash
npm i -g vercel
vercel login
vercel
```

## Post-Deployment

1. **Update CORS** (if needed):
   - The backend already allows all origins (`allow_origins=["*"]`)
   - This should work for most deployments

2. **Test the API**:
   - Visit your deployed URL
   - Try assembling: `mov rax, rbx`
   - Try disassembling: `48 89 d8`

3. **Custom Domain** (optional):
   - Most platforms allow custom domains
   - Update DNS settings as per platform instructions

## Troubleshooting

### Issue: Native library compilation fails
**Solution**: Use Railway or Render - they have better support for native dependencies.

### Issue: API calls return 404
**Solution**: Check your routing configuration. Make sure API routes are properly set up.

### Issue: CORS errors
**Solution**: The backend already allows all origins. If issues persist, check your platform's CORS settings.

### Issue: Timeout errors
**Solution**: Increase timeout in platform settings (Railway/Render allow this).

## Recommended Platform

**Railway** is recommended because:
- ✅ Excellent Python support
- ✅ Native library compilation works
- ✅ Free tier available
- ✅ Easy GitHub integration
- ✅ Automatic HTTPS
- ✅ Simple deployment
