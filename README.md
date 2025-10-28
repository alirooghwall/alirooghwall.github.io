# MARS EMPIRE - MLM Companion App

A comprehensive web application for Multi-Level Marketing (MLM) management, featuring user authentication, tree visualization, checklists, articles, resources, and AI-powered assistance.

## Features

- **User Authentication**: Sign up, sign in, Google OAuth integration
- **Dashboard**: Personalized user dashboard
- **MLM Tree Visualization**: Interactive tree view of network hierarchy
- **Checklists**: Predefined and custom checklists for MLM tasks
- **Articles & Resources**: Content management system
- **Calculator**: MLM commission calculator
- **Leaderboard**: Performance tracking
- **Admin Panel**: User management, content creation
- **Responsive Design**: Mobile-friendly interface

## Tech Stack

- **Backend**: Node.js, Express.js
- **Database**: MongoDB with Mongoose
- **Frontend**: HTML5, CSS3, JavaScript, EJS templates
- **Authentication**: JWT, bcrypt, Passport.js (Google OAuth)
- **Email**: Nodemailer
- **Logging**: Winston
- **File Upload**: Multer

## Prerequisites

- Node.js (v14 or higher)
- MongoDB (local or cloud instance)
- Gmail account for email notifications

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/alirooghwall/alirooghwall.github.io.git
   cd alirooghwall.github.io
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Set up environment variables**:
   - Copy `.env.example` to `.env`
   - Fill in your actual values:
     ```env
     JWT_SECRET=your_secure_jwt_secret
     MONGO_URI=mongodb://localhost:27017/mars-empire
     EMAIL_USER=your_gmail@gmail.com
     EMAIL_PASS=your_gmail_app_password
     BASE_URL=http://localhost:3000
     GOOGLE_CLIENT_ID=your_google_client_id
     GOOGLE_CLIENT_SECRET=your_google_client_secret
     NODE_ENV=development
     PORT=3000
     ```

4. **Set up MongoDB**:
   - Install MongoDB locally or use a cloud service like MongoDB Atlas
   - Update `MONGO_URI` in `.env`

5. **Configure Google OAuth** (optional):
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing
   - Enable Google+ API
   - Create OAuth 2.0 credentials
   - Add authorized redirect URIs: `http://localhost:3000/auth/google/callback`
   - Update `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env`

## Running the Application

### Development
```bash
npm start
# or
node server.js
```

The application will be available at `http://localhost:3000`

### Production
```bash
NODE_ENV=production node server.js
```

## Default Admin Account

After first run, a default admin account is created:
- **Email**: admin@alirooghwall.github.io
- **Password**: admin123

## API Endpoints

### Authentication
- `GET /signin` - Sign in page
- `POST /signin` - Sign in
- `GET /signup` - Sign up page
- `POST /signup` - Sign up
- `POST /logout` - Logout
- `GET /check-auth` - Check authentication status

### Protected Routes (require authentication)
- `GET /dashboard` - User dashboard
- `GET /profile` - User profile
- `GET /rules` - Rules page
- `GET /articles` - Articles page
- `GET /resources` - Resources page
- `GET /checklists` - Checklists page
- `GET /tree` - MLM tree visualization
- `GET /calculator` - Calculator page
- `GET /leaderboard` - Leaderboard page

### Admin Routes (require admin privileges)
- `GET /admin` - Admin dashboard
- `POST /admin/*` - Admin operations

## Project Structure

```
├── assets/                 # Static assets (CSS, JS, images)
├── models/                 # Mongoose models
├── routes/                 # Route handlers
├── utils/                  # Utility functions
├── views/                  # EJS templates
├── logs/                   # Application logs
├── uploads/                # Uploaded files
├── server.js               # Main application file
├── package.json            # Dependencies and scripts
├── .env.example            # Environment variables template
└── README.md               # This file
```

## Deployment

### Render.com
1. Connect your GitHub repository to Render
2. Set environment variables in Render dashboard
3. Deploy the service
4. Update `BASE_URL` to your Render URL

### Other Platforms
- Ensure all environment variables are set
- Use a production MongoDB instance
- Configure reverse proxy if needed

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support or questions, please contact the development team or create an issue in the repository.

---

**Note**: This application is designed for educational and demonstration purposes. Ensure compliance with local laws and regulations regarding MLM operations.
