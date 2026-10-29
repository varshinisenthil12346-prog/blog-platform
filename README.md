# Blog Platform with Comments

Node.js + Express + SQLite + vanilla JS frontend.

## Run
```
npm install
npm start
```
Open http://localhost:3000

(Optional) set `JWT_SECRET` and `PORT` environment variables.

## Features
- Register, login (bcrypt + JWT)
- Create, edit, delete your own posts
- Comment on posts, delete your own comments
- RESTful API with SQLite database (blog.db auto-created)

## API
| Method | Endpoint | Auth |
|---|---|---|
| POST | /api/auth/register | no |
| POST | /api/auth/login | no |
| GET | /api/posts | no |
| GET | /api/posts/:id | no |
| POST | /api/posts | yes |
| PUT | /api/posts/:id | owner |
| DELETE | /api/posts/:id | owner |
| POST | /api/posts/:id/comments | yes |
| DELETE | /api/comments/:id | owner |
