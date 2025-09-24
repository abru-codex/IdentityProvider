# Identity Provider

A simple OAuth 2.0 and OpenID Connect identity provider built with .NET

## Features

### Core Authentication
- **OAuth 2.0 & OpenID Connect**: Full implementation of OAuth 2.0 authorization framework and OpenID Connect authentication layer
- **JWT Token Support**: Secure token generation and validation using JSON Web Tokens
- **PKCE Support**: Proof Key for Code Exchange for enhanced security in public clients
- **Refresh Tokens**: Long-lived refresh token support for seamless user experience

### User & Access Management
- **User Management**: Complete user registration, login, and profile management
- **Role-Based Access Control (RBAC)**: Granular role and permission management system
- **Password Policies**: Configurable password complexity requirements and lockout policies

### Performance
- **Redis Caching**: High-performance caching layer for user permissions and session data

## Technology Stack

- **Framework**: .NET 9.0
- **Database**: PostgreSQL
- **Caching**: Redis
- **Authentication**: ASP.NET Core Identity
- **Validation**: FluentValidation
- **Token Management**: JWT Bearer Authentication
- **Frontend**: Razor Views, Bootstrap 5

## Prerequisites

- .NET 9.0 SDK
- PostgreSQL 13+
- Redis 6.0+
