import express from "express";
import mysql from "mysql";
import bcrypt from "bcrypt";
const app = express();

app.use(express.json())

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(5000,()=>{
    console.log("Server is running on port 5000")
})
const db = mysql.createConnection({
  host:"localhost",
  user:"root",
  password:"",
  database:"auth",
});
function isValidJSON(text) {
  if (typeof text !== "string") {
    return false; // JSON input must be a string
  }
  try {
    JSON.parse(text);
    return true; // Parsing succeeded, it is valid JSON
  } catch (e) {
    return false; // An error occurred, it is invalid JSON
  }
}
app.post('/register', (req, res) => {
     if (!req.body) {
    return res.status(400).json({ error: "Request body is missing." });
  }

  if (!isValidJSON(JSON.stringify(req.body))) {
    return res.status(400).json({ error: "Invalid JSON format." });
  }

  const { username, email, phone, password } = req.body;
  const errors = [];
  if (!username) {
    errors.push("username is required.");
  }
  if (!email) {
    errors.push("Email is required.");
  }
  if (!password) {
    errors.push("Password is required.");
  }

  if (errors.length > 0) {
    return res.status(400).json({ errors: errors });
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Invalid email format" });
  }
  if (password.length < 6) {
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters" });
    }
  if (username.length < 3) {
      return res
        .status(400)
        .json({ error: "Username must be at least 3 characters" });
    }
    
 const emailCountQuery ="SELECT COUNT(*) AS count FROM users WHERE email = ?";
  db.query(emailCountQuery, [email], (err, result) => {
  if (err) {
    console.error(err);
    return res.status(500).json({ error: "Database error" });
  }
  if ( result[0].count >= 3) {
    return res.status(400).json({ error: "This email has reached the maximum number of accounts" });
  }
console.log("Email count:", result[0].count);

  const checkuserQuery =
      "SELECT id FROM users WHERE username = ?";
    db.query(checkuserQuery, [username], async (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Database error" });
      }

      if (result.length > 0) {
        return res
          .status(404)
          .json({ error: "username already exists" });
      }

  const hashedPassword = await bcrypt.hash(password, 10);

    const query = "INSERT INTO users (username, email, hashedPassword, Phone) VALUES (?, ?, ?, ?)";
      db.query(query, [username, email, hashedPassword, phone], (err, result) => {
       if (err) {
      if (err.code === "ECONNREFUSED") {
        return res
          .status(500)
          .json({ error: "Database connection was refused." });
      }
      if (err.code === "ER_DUP_ENTRY") {
        return res.status(400).json({ error: err.sqlMessage });
      }
      console.log(err);
      return res.status(500).json({ error: err.sqlMessage });
    } else {
          res.status(200).send("User registered successfully");
        }
      });
    });
  });
   });


   app.post('/login', (req, res) => {{}
    if (!req.body) {
    return res.status(400).json({ error: "Request body is missing." });
  }

  if (!isValidJSON(JSON.stringify(req.body))) {
    return res.status(400).json({ error: "Invalid JSON format." });
  }

   const {username, email, password } = req.body;
  const errors = [];
  if (!username || !email) {
    errors.push("username or email are required.");
  }
  if (!password) {
    errors.push("Password is required.");
  }

  if (errors.length > 0) {
    return res.status(400).json({ errors: errors });
  }
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Invalid email format" });
  }
  if (password.length < 6) {
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters" });
    }
  if (username.length < 3) {
      return res
        .status(400)
        .json({ error: "Username must be at least 3 characters" });
    }

    const query = "SELECT * FROM users WHERE email = ? OR username = ?";
    db.query(query, [email,username], async (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Database error" });
      }
      if (result.length === 0) {
        return res.status(401).json({ error: "Invalid email or password" });//401 not 404 krml l security 
      }
     
      const user = result[0];
      const hashedpassword = await bcrypt.hash(password, 10);
      console.log("hashedPassword from request:", hashedpassword);
      console.log("Hashed password from DB:", user.hashedPassword);
     const isPasswordValid = await bcrypt.compare(password, user.hashedPassword); 
      console.log("Password is valid?", isPasswordValid);
      if (!isPasswordValid) {
        return res.status(401).json({ error: "Invalid email or password" });
      }
      res.status(200).json({ message: "Login successful", user });
    });
  });