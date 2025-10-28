const BASE_URL = process.env.BASE_URL || 'https://mars-empire-mlm.onrender.com';

const emailTemplates = {
  verification: (token) => `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Verify Your Email - MARS EMPIRE</title>
      <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { text-align: center; background: linear-gradient(135deg, #1e1e2e, #2a2a3e); color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { padding: 20px; }
        .button { display: inline-block; background-color: #4ecdc4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>MARS EMPIRE</h1>
          <p>Email Verification</p>
        </div>
        <div class="content">
          <h2>Welcome to MARS EMPIRE!</h2>
          <p>Please verify your email address to complete your registration.</p>
          <a href="${BASE_URL}/verify/${token}" class="button">Verify Email</a>
          <p>If the button doesn't work, copy and paste this link into your browser:</p>
          <p>${BASE_URL}/verify/${token}</p>
        </div>
        <div class="footer">
          <p>&copy; 2025 MARS EMPIRE. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `,

  welcome: (name) => `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Welcome to MARS EMPIRE</title>
      <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { text-align: center; background: linear-gradient(135deg, #1e1e2e, #2a2a3e); color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { padding: 20px; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>MARS EMPIRE</h1>
          <p>Welcome!</p>
        </div>
        <div class="content">
          <h2>Hello ${name}!</h2>
          <p>Welcome to MARS EMPIRE! Your account has been approved and you can now access all features.</p>
          <p>Start exploring our resources and building your network.</p>
          <a href="${BASE_URL}/dashboard">Go to Dashboard</a>
        </div>
        <div class="footer">
          <p>&copy; 2025 MARS EMPIRE. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `,

  passwordReset: (token) => `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Reset Your Password - MARS EMPIRE</title>
      <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { text-align: center; background: linear-gradient(135deg, #1e1e2e, #2a2a3e); color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { padding: 20px; }
        .button { display: inline-block; background-color: #ff6b6b; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>MARS EMPIRE</h1>
          <p>Password Reset</p>
        </div>
        <div class="content">
          <h2>Reset Your Password</h2>
          <p>You requested a password reset. Click the button below to set a new password.</p>
          <a href="${BASE_URL}/reset-password/${token}" class="button">Reset Password</a>
          <p>If the button doesn't work, copy and paste this link into your browser:</p>
          <p>${BASE_URL}/reset-password/${token}</p>
          <p>This link will expire in 1 hour.</p>
        </div>
        <div class="footer">
          <p>&copy; 2025 MARS EMPIRE. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `,

  notification: (title, message) => `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Notification - MARS EMPIRE</title>
      <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { text-align: center; background: linear-gradient(135deg, #1e1e2e, #2a2a3e); color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { padding: 20px; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>MARS EMPIRE</h1>
          <p>Notification</p>
        </div>
        <div class="content">
          <h2>${title}</h2>
          <p>${message}</p>
        </div>
        <div class="footer">
          <p>&copy; 2025 MARS EMPIRE. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `
};

module.exports = emailTemplates;