# Deploy to GitHub

Follow these steps to push this project to GitHub.

## 1. Create a new repository on GitHub

1. Go to [github.com/new](https://github.com/new)
2. Set **Repository name** to: `crypto-toolkit`
3. Add a description: `Python cryptography library - classical and modern encryption`
4. Choose **Public**
5. Do **not** initialize with README, .gitignore, or license (this repo already has them)
6. Click **Create repository**

## 2. Push from your machine

In your terminal, run (replace `YOUR_USERNAME` with your GitHub username):

```bash
cd "c:\Users\user\OneDrive\Desktop\crypto-toolkit"

# Add your GitHub repo as remote
git remote add origin https://github.com/YOUR_USERNAME/crypto-toolkit.git

# Rename branch to main (optional, GitHub default)
git branch -M main

# Push to GitHub
git push -u origin main
```

If you use **SSH** instead of HTTPS:

```bash
git remote add origin git@github.com:YOUR_USERNAME/crypto-toolkit.git
git branch -M main
git push -u origin main
```

## 3. Update the README (optional)

After pushing, replace `YOUR_USERNAME` in `README.md` with your actual GitHub username so the clone URL is correct.
