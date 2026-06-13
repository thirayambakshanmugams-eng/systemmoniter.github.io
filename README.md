# SysMon Pro Deployment

This repo contains a desktop Electron app and a Flask backend.

## Deploy as a global web app

### 1. Deploy the backend to Render

1. Create a new GitHub repo from this project.
2. Connect it to Render.
3. Use `render.yaml` in the repo root.
4. Set the build command to:
   ```bash
   pip install -r requirements.txt
   ```
5. Set the start command to:
   ```bash
   python backend/server.py
   ```
6. Use port `5000` in the environment.

Render will expose your backend at a public URL like:

```text
https://your-render-backend.onrender.com
```

### 1.5 Run locally as a website

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the Flask backend from the project root:
   ```bash
   python backend/server.py
   ```
3. Open a browser at:
   ```text
   http://127.0.0.1:5000/
   ```

The backend now serves the `frontend/index.html` web app directly and the app will fetch `/api/*` endpoints relative to the same origin.

### 2. Deploy the frontend to Netlify

1. Deploy the `frontend/` folder as a static site.
2. Use `netlify.toml` in the root.
3. The static publish directory is `frontend`.
4. Netlify will automatically upload `_redirects` and proxy `/api/*` to your backend.

### 3. Configure the proxy

Edit `frontend/_redirects` and replace:

```text
/api/*  https://YOUR_RENDER_BACKEND_URL/:splat  200
```

with your actual Render backend URL.

### 4. Verify frontend behavior

The frontend is now configured to use:

- `http://127.0.0.1:5000` when run from Electron/file protocol
- relative `/api/...` when served from the web

This allows the same UI to work both locally and on the internet.

## Deploy as a desktop app (Electron)

1. Install dependencies:
   ```bash
   npm install
   pip install -r requirements.txt
   ```
2. Launch locally:
   ```bash
   npm start
   ```

## Notes

- If you deploy the frontend and backend separately, make sure the Netlify proxy target is set correctly.
- For production use, switch from Flask development server to a proper WSGI service if needed.

## GitHub Actions deployment

A GitHub Actions workflow is included at `.github/workflows/deploy.yml`.

### Setup

1. Add the following GitHub secrets to your repository:
   - `NETLIFY_AUTH_TOKEN`
   - `NETLIFY_SITE_ID`

2. Push to `main`.

### What it does

- installs backend and frontend dependencies
- deploys the `frontend/` folder to Netlify using Netlify CLI

### Notes

- The backend deployment is handled by Render using `render.yaml`.
- Render can deploy automatically when you connect the repo to Render and enable GitHub integration.
