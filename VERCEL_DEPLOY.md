# 🚀 Step-by-Step Vercel Deployment Guide

## Prerequisites
- GitHub account
- Vercel account (free at https://vercel.com)
- Git installed on your computer

---

## Step 1: Push Your Code to GitHub

### 1.1 Initialize Git (if not done):
```bash
git init
```

### 1.2 Add all files:
```bash
git add .
```

### 1.3 Commit:
```bash
git commit -m "Ready for Vercel deployment"
```

### 1.4 Create GitHub Repository:
1. Go to https://github.com/new
2. Create a new repository (e.g., `broitsjustassembly`)
3. **DON'T** initialize with README (you already have files)
4. Click "Create repository"

### 1.5 Push to GitHub:
```bash
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
git branch -M main
git push -u origin main
```

Replace `YOUR_USERNAME` and `YOUR_REPO_NAME` with your actual GitHub username and repository name.

---

## Step 2: Install Vercel CLI (Optional but Recommended)

### Option A: Using npm (if you have Node.js):
```bash
npm install -g vercel
```

### Option B: Using PowerShell (Windows):
```powershell
npm install -g vercel
```

### Verify installation:
```bash
vercel --version
```

---

## Step 3: Deploy to Vercel

### Method 1: Using Vercel CLI (Fastest)

1. **Login to Vercel:**
   ```bash
   vercel login
   ```
   - This will open your browser
   - Authorize Vercel CLI

2. **Deploy:**
   ```bash
   vercel
   ```
   - Follow the prompts:
     - Set up and deploy? **Y**
     - Which scope? (Select your account)
     - Link to existing project? **N**
     - Project name? (Press Enter for default)
     - Directory? (Press Enter for `.`)
     - Override settings? **N**

3. **Deploy to Production:**
   ```bash
   vercel --prod
   ```

4. **Get your URL:**
   - Vercel will give you a URL like: `https://your-project.vercel.app`
   - Your app is live! 🎉

### Method 2: Using Vercel Dashboard (Easier for Beginners)

1. **Go to Vercel:**
   - Visit: https://vercel.com
   - Sign up/Login (can use GitHub)

2. **Import Project:**
   - Click "Add New..." → "Project"
   - Click "Import Git Repository"
   - Select your GitHub repository
   - Click "Import"

3. **Configure Project:**
   - **Framework Preset:** Other
   - **Root Directory:** `./` (leave as is)
   - **Build Command:** (leave empty - not needed)
   - **Output Directory:** (leave empty)
   - **Install Command:** (leave empty)
   - Click "Deploy"

4. **Wait for Deployment:**
   - Vercel will automatically:
     - Install dependencies from `api/requirements.txt`
     - Build your Python functions
     - Deploy your frontend

5. **Get your URL:**
   - Once deployed, you'll see: `https://your-project.vercel.app`
   - Click the URL to visit your app!

---

## Step 4: Configure Environment (If Needed)

If your deployment fails or you need to adjust settings:

1. **Go to Vercel Dashboard** → Your Project → Settings
2. **Functions:**
   - Memory: 1024 MB (or higher if needed)
   - Max Duration: 30 seconds
3. **Environment Variables:**
   - Add any variables if needed (usually not required)

---

## Step 5: Test Your Deployment

1. **Visit your Vercel URL:**
   - Example: `https://your-project.vercel.app`

2. **Test Assembler:**
   - Enter: `mov rax, rbx`
   - Click "Assemble"
   - Should see hex output

3. **Test Disassembler:**
   - Enter: `48 89 d8`
   - Click "Disassemble"
   - Should see assembly instructions

---

## ⚠️ Important Notes

### Potential Issues with Native Libraries:

**Keystone-engine** and **Capstone** are native libraries that compile C code. Vercel may have issues with these:

1. **If deployment fails:**
   - Check Vercel logs for build errors
   - The error might mention "keystone" or "capstone" compilation issues

2. **Alternative Solutions:**
   - Try Railway instead (better for native libraries)
   - Or use Docker deployment (more complex)

3. **Workaround (if needed):**
   - You may need to use pre-built wheels
   - Or switch to a platform that supports native libraries better

---

## 📁 Project Structure for Vercel

Your project should have:
```
Assembler/
├── api/
│   ├── index.py          ✅ Vercel serverless function
│   └── requirements.txt  ✅ Python dependencies
├── backend/
│   ├── main.py          ✅ FastAPI app
│   └── requirements.txt
├── frontend/
│   └── index.html       ✅ Frontend
├── public/
│   └── index.html       ✅ Static files for Vercel
├── vercel.json          ✅ Vercel configuration
└── requirements.txt     ✅ Root requirements (backup)
```

---

## 🔄 Updating Your Deployment

Every time you push to GitHub:

```bash
git add .
git commit -m "Update app"
git push
```

**Vercel will automatically redeploy!** (if you connected via GitHub)

Or manually:
```bash
vercel --prod
```

---

## 🆘 Troubleshooting

### Issue: "Module not found"
**Solution:** Check that `api/requirements.txt` exists and has all dependencies.

### Issue: "Function timeout"
**Solution:** Increase `maxDuration` in `vercel.json` (max is 60 seconds on Pro plan).

### Issue: "Native library compilation failed"
**Solution:** Vercel may not support keystone-engine/capstone. Try Railway instead.

### Issue: "404 on /api routes"
**Solution:** Check `vercel.json` routing configuration.

### Issue: "Frontend not loading"
**Solution:** Make sure `public/index.html` exists and routes are correct.

---

## ✅ Success Checklist

- [ ] Code pushed to GitHub
- [ ] Vercel account created
- [ ] Project imported/deployed
- [ ] All routes working (`/` and `/api/*`)
- [ ] Assembler working
- [ ] Disassembler working
- [ ] Custom domain set up (optional)

---

## 🎉 You're Done!

Your app should now be live on Vercel! Share your URL: `https://your-project.vercel.app`

---

## 📚 Additional Resources

- Vercel Docs: https://vercel.com/docs
- Vercel Python: https://vercel.com/docs/concepts/functions/serverless-functions/runtimes/python
- Vercel Support: https://vercel.com/support
