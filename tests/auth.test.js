const request = require('supertest');
const express = require('express');
const jwt = require('jsonwebtoken');

// Mock the User model
jest.mock('../models/User', () => {
  const mockUser = jest.fn().mockImplementation((data) => ({
    ...data,
    save: jest.fn().mockResolvedValue(data),
    comparePassword: jest.fn()
  }));

  mockUser.findOne = jest.fn();

  return mockUser;
});

const User = require('../models/User');

// Mock the auth router
const authRouter = require('../routes/auth');

const app = express();
app.use(express.json());
app.use('/auth', authRouter);

describe('Auth Routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /auth/signup', () => {
    test('should create a new user successfully', async () => {
      const userData = {
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123'
      };

      User.mockImplementation(() => ({
        ...userData,
        save: jest.fn().mockResolvedValue(userData)
      }));

      const response = await request(app)
        .post('/auth/signup')
        .send(userData);

      expect(response.status).toBe(201);
      expect(response.body.message).toBe('User created successfully');
    });

    test('should handle signup errors', async () => {
      User.mockImplementation(() => ({
        save: jest.fn().mockRejectedValue(new Error('Database error'))
      }));

      const response = await request(app)
        .post('/auth/signup')
        .send({
          name: 'Test User',
          email: 'test@example.com',
          password: 'password123'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Database error');
    });
  });

  describe('POST /auth/signin', () => {
    test('should sign in user successfully', async () => {
      const mockUser = {
        _id: 'user123',
        name: 'Test User',
        email: 'test@example.com',
        comparePassword: jest.fn().mockResolvedValue(true)
      };

      User.findOne.mockResolvedValue(mockUser);

      // Mock JWT sign
      jwt.sign = jest.fn().mockReturnValue('mock-jwt-token');

      const response = await request(app)
        .post('/auth/signin')
        .send({
          email: 'test@example.com',
          password: 'password123'
        });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Signed in successfully');
      expect(response.body.token).toBe('mock-jwt-token');
      expect(response.body.user).toEqual({
        name: 'Test User',
        email: 'test@example.com'
      });
    });

    test('should return error for non-existent user', async () => {
      User.findOne.mockResolvedValue(null);

      const response = await request(app)
        .post('/auth/signin')
        .send({
          email: 'nonexistent@example.com',
          password: 'password123'
        });

      expect(response.status).toBe(404);
      expect(response.body.error).toBe('User not found');
    });

    test('should return error for invalid password', async () => {
      const mockUser = {
        comparePassword: jest.fn().mockResolvedValue(false)
      };

      User.findOne.mockResolvedValue(mockUser);

      const response = await request(app)
        .post('/auth/signin')
        .send({
          email: 'test@example.com',
          password: 'wrongpassword'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Invalid password');
    });
  });
});