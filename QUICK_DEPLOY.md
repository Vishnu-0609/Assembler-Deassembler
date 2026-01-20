# 🚀 Quick Deployment Guide

## ⚡ Fastest Option: Railway (Recommended)

Railway is the easiest and most reliable for this project.

### Step-by-Step:

1. **Push your code to GitHub** (if not already):
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
   git push -u origin main
   ```

2. **Go to Railway**:
   - Visit: https://railway.app
   - Click "Start a New Project"
   - Sign up/login with GitHub

3. **Deploy**:
   - Click "Deploy from GitHub repo"
   - Select your repository
   - Railway auto-detects Python
   - It will automatically:
     - Install dependencies from `backend/requirements.txt`
     - Run the app using `Procfile`

4. **Get your URL**:
   - Railway gives you a URL like: `https://your-app.railway.app`
   - Your app is live! 🎉

5. **Optional - Custom Domain**:
   - Click on your project → Settings → Domains
   - Add your custom domain

---

## 🎯 Alternative: Render (Also Easy)

1. **Go to Render**: https://render.com
2. **Sign up/login** with GitHub
3. **Click "New" → "Web Service"**
4. **Connect your GitHub repo**
5. **Settings**:
   - **Build Command**: `pip install -r backend/requirements.txt`
   - **Start Command**: `cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT`
6. **Click "Create Web Service"**
7. **Done!** Your app will be live in a few minutes

---

## ⚠️ Vercel (May Have Issues)

Vercel might have problems with native libraries (keystone-engine, capstone).

### If you want to try Vercel:

1. **Install Vercel CLI**:
   ```bash
   npm install -g vercel
   ```

2. **Login**:
   ```bash
   vercel login
   ```

3. **Deploy**:
   ```bash
   vercel
   ```

4. **If it fails**, use Railway or Render instead.

---

## 📝 Pre-Deployment Checklist

- [ ] Code is pushed to GitHub
- [ ] `backend/requirements.txt` is up to date
- [ ] `Procfile` exists (✅ already created)
- [ ] Frontend uses relative API paths `/api/...` (✅ already done)

---

## 🎉 After Deployment

1. **Test your app**:
   - Visit your deployed URL
   - Try assembling: `mov rax, rbx`
   - Try disassembling: `48 89 d8`

2. **Share your link**:
   - Your app is now live!
   - Share with friends: `https://your-app.railway.app`

---

## 💡 Pro Tips

- **Railway** gives you $5 free credit monthly
- **Render** has a free tier (spins down after inactivity)
- Both platforms auto-deploy on git push
- Both provide HTTPS automatically
- Both support custom domains

---

## 🆘 Need Help?

- Check `DEPLOYMENT.md` for detailed instructions
- Railway docs: https://docs.railway.app
- Render docs: https://render.com/docs
