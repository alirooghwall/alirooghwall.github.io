# MARS EMPIRE - MLM Companion Website

A comprehensive web platform for MLM (Multi-Level Marketing) education, management, and community building.

## Features

- User authentication with roles
- Content management (Rules, Articles, Resources)
- Interactive checklists with progress tracking
- Commission calculator
- Leaderboard with gamification
- Tree view for network visualization
- Admin dashboard with tabbed sections
- File upload functionality
- AI integration
- Mobile-responsive design

## Setup

1. Clone the repository
2. Install dependencies: `npm install`
3. Set up environment variables in `.env`:
   - `MONGO_URI`: MongoDB connection string
   - `JWT_SECRET`: Secret for JWT tokens
   - `EMAIL_USER`: Gmail for sending emails
   - `EMAIL_PASS`: Gmail app password
   - `BASE_URL`: Base URL of the app (e.g., https://mars-empire-mlm.onrender.com)
   - `GOOGLE_CLIENT_ID`: Google OAuth client ID
   - `GOOGLE_CLIENT_SECRET`: Google OAuth client secret
4. Run the server: `npm start`

### Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Set authorized redirect URIs to: `https://yourdomain.com/auth/google/callback` (for production) and `http://localhost:3000/auth/google/callback` (for local)
6. Add the client ID and secret to your `.env` file

## Deployment

Deploy to Render or similar platform. Ensure environment variables are set.
