import express from "express";
import mysql from "mysql";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();
const app = express();

app.use(express.json())

app.get('/', (req, res) => {
  res.send('Hello World!');
});

//app.listen(5000,()=>{
 //   console.log("Server is running on port 5000")
//})
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const db = mysql.createConnection({
  host:"localhost",
  user:"root",
  password:"",
  database:"auth",
});
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}
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
          res.status(200).send({message:"User registered successfully"});
        }
      });
    });
  });
   });


   app.post('/login', (req, res) => {
    if (!req.body) {
    return res.status(400).json({ error: "Request body is missing." });
  }

  if (!isValidJSON(JSON.stringify(req.body))) {
    return res.status(400).json({ error: "Invalid JSON format." });
  }

   const {identifier, password } = req.body;
  const errors = [];
  if (!identifier) {
    errors.push("username or email are required.");
  }
  if (!password) {
    errors.push("Password is required.");
  }

  if (errors.length > 0) {
    return res.status(400).json({ errors: errors });
  }



  if (password.length < 6) {
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters" });
    }
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const isEmail = emailRegex.test(identifier);

  const query = isEmail //is email hye l condition
    ? "SELECT * FROM users WHERE email = ?" //haydi mtl if true
    : "SELECT * FROM users WHERE username = ?";// if false 

   
    db.query(query, [identifier], async (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Database error" });
      }
      if (result.length === 0) {
        return res.status(401).json({ error: "Invalid credentials" });//401 not 404 krml l security 
      }
     
      const user = result[0];
      const hashedpassword = await bcrypt.hash(password, 10);
      console.log("hashedPassword from request:", hashedpassword);
      console.log("Hashed password from DB:", user.hashedPassword);
     const isPasswordValid = await bcrypt.compare(password, user.hashedPassword); 
      console.log("Password is valid?", isPasswordValid);
      if (!isPasswordValid) {
        return res.status(401).json({ error: "Invalid credentials" });
      }
      const token = jwt.sign(
        {
         id: user.id,
         username: user.username,
         email: user.email
         },
        process.env.JWT_SECRET,
       { expiresIn: "1h" }
      );
      res.status(200).json({ message: "Login successful", token: token  });
    });
  });

  app.get("/profile", authenticateToken, (req, res) => {
    const query = "SELECT id, username FROM users WHERE id = ?";
    db.query(query, [req.user.id], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Database error" });
      }
      if (result.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }
      res.status(200).json({ user: result[0] });
    });
  });


  app.put("/updateprofile", authenticateToken, (req, res) => {
    if (!req.body) {
    return res.status(400).json({ error: "Request body is missing." });
  }
   if (!isValidJSON(JSON.stringify(req.body))) {
    return res.status(400).json({ error: "Invalid JSON format." });
  }
    const userId = req.id;
    const { username, email, phone } = req.body;
     const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Invalid email format" });
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
  const checkuserQuery =
      "SELECT id FROM users WHERE username = ? AND id != ?";//krml y3ml check iza  fi user bl data base mtl l updated user yli be3tinu bl req
    db.query(checkuserQuery, [username, userId], async (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Database error" });
      }

      if (result.length > 0) {
        return res
          .status(404)
          .json({ error: "username already exists" });
      }

    const query = "UPDATE users SET username = ?, email = ?, Phone = ? WHERE id = ?";
    db.query(query, [username, email, phone, req.user.id], (err, result) => {
     
    if (err) {
        if (err.code === "ER_DUP_ENTRY") {
        return res.status(400).json({ error: err.sqlMessage });
      }
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "User not found" });
      }
        res.status(200).json({ message: "Profile updated successfully" });
      });
    });
    });
  });


  app.post("/forgotpassword", (req, res) => {//sta3malna post msh put laan 3m n3ml action (create mn jdid)
    
    const {identifier, newpassword } = req.body;
     const errors = [];
  if (!identifier) {
    errors.push("username or email are required.");
  }
  if (!newpassword) {
    errors.push("Password is required.");
  }

  if (errors.length > 0) {
    return res.status(400).json({ errors: errors });
  }



  if (newpassword.length < 6) {
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters" });
    }
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const isEmail = emailRegex.test(identifier);

  const query = isEmail //is email hye l condition
    ? "SELECT * FROM users WHERE email = ?" //haydi mtl if true
    : "SELECT * FROM users WHERE username = ?";// if false 

    db.query(query, [identifier], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Database error" });
      }
      if (result.length === 0) {
        return res.status(404).json({ error: "credentials not found" });
      }
    
      const resetToken = jwt.sign(
        { id: result[0].id },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );
      res.status(200).json({ message: "Password reset link sent", token: resetToken });
    });
  });
  //bhyda l api 3ndi mshkle enu iza l email 3le aktar mn user rah yghyr lal kl 