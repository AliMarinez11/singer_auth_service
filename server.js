//This loads database credentials from .env file.
require('dotenv').config();

//This imports express which is a framework for handling http requests.
const express = require('express');

//This is a library for hashing passwords. I might change this in the future though. I want to understand this better before committing to one, I only used this because I've used it in the past when messing around.
const bcrypt = require('bcrypt');

//This is for handling json web tokens which travel in the header of requests and are used for authenticating requests/users.
const jwt = require('jsonwebtoken');

//This allows us to interact with PostgreSQL, our database.
const { Pool } = require('pg');

//Creates express instance.
const app = express();

//Creates a connection to our PostgreSQL database using the credentials from the .env file.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

//This parses json and makes data available in body.
app.use(express.json());

//This is the base route.
app.get('/', (req, res) => {
  res.send('Authentication Service is running');
});

//This checks if there is a port specified already and if not uses port 4000, and then starts the server.
const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});


//This is the sign Up Route
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
  
    //This checks if user already exists.
    const userExists = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ message: 'Username already taken' });
    }
  
    //This hashes the password.
    const passwordHash = await bcrypt.hash(password, 10);
  
    //This stores the new user in the database.
    await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2)',
      [username, passwordHash]
    );
  
    res.status(201).json({ message: 'User created successfully' });
  });



  //This is the login route.
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
  
    //This checks if the user exists.
    const user = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (user.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }
  
    //This makes sure the password is valid.
    const isPasswordValid = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }
  
    //This generates JWT
    const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' });
  
    res.json({ token, message: `Welcome, ${username}!` });
  });