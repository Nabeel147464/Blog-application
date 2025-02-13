# Blogging Platform API

## Overview
This is a backend API for a blogging platform that allows users to register and manage blog posts.

## Features
- Register a new user
- Create, retrieve, update, and delete blog posts
- Authentication for blog post management

## Endpoints
1. **POST /users**: Register a new user.
2. **POST /blogs**: Create a blog post (title, content, tags).
3. **GET /blogs**: Retrieve all blogs.
4. **GET /blogs/:id**: Retrieve a single blog post.
5. **PUT /blogs/:id**: Update a blog post (owner only).
6. **DELETE /blogs/:id**: Delete a blog post (owner only).

## Installation
1. Clone the repository.
2. Install the dependencies:
   ```
   npm install
   ```
3. Run the application:
   ```
   npm start
