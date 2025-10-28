const emailTemplates = require('../utils/emailTemplates');

describe('Email Templates', () => {
  test('verification template should contain verification link', () => {
    const token = 'test-token-123';
    const template = emailTemplates.verification(token);

    expect(template).toContain('Verify Email');
    expect(template).toContain(token);
    expect(template).toContain('MARS EMPIRE');
  });

  test('welcome template should contain user name', () => {
    const name = 'John Doe';
    const template = emailTemplates.welcome(name);

    expect(template).toContain('Welcome!');
    expect(template).toContain(name);
    expect(template).toContain('Go to Dashboard');
  });

  test('password reset template should contain reset link', () => {
    const token = 'reset-token-456';
    const template = emailTemplates.passwordReset(token);

    expect(template).toContain('Reset Password');
    expect(template).toContain(token);
    expect(template).toContain('expire in 1 hour');
  });

  test('notification template should contain title and message', () => {
    const title = 'Test Notification';
    const message = 'This is a test message';
    const template = emailTemplates.notification(title, message);

    expect(template).toContain(title);
    expect(template).toContain(message);
    expect(template).toContain('Notification');
  });

  test('all templates should be valid HTML', () => {
    const token = 'test-token';
    const name = 'Test User';
    const title = 'Test';
    const message = 'Message';

    const templates = [
      emailTemplates.verification(token),
      emailTemplates.welcome(name),
      emailTemplates.passwordReset(token),
      emailTemplates.notification(title, message)
    ];

    templates.forEach(template => {
      expect(template).toContain('<!DOCTYPE html>');
      expect(template).toContain('<html');
      expect(template).toContain('<head>');
      expect(template).toContain('<body>');
    });
  });
});