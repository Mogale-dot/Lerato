

// Load Environment Variables
// ================================
require('dotenv').config();

// ================================
// Import Required Packages
// ================================
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
// ================================
// Initialize Express App
// ================================
const app = express();

app.use(cors());
app.use(express.json()); // To parse JSON bodies
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ================================
// Configure MySQL Connection
// ================================
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME  

});

db.connect((err) => {
  if (err) {
    console.error('❌ MySQL Connection Failed:', err);
    return;
  }
  console.log('✅ Connected to MySQL Database');
});

// ================================
// Configure Nodemailer for Emails
// ================================
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,     
  port: process.env.EMAIL_PORT,     
  secure: false,                     
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ================================
// Configure Multer for File Uploads (Media)
// ================================
const fs = require('fs');


// Ensure directories for uploads exist:
const eventUploadDir = path.join(__dirname, 'uploads/events');
const mediaUploadDir = path.join(__dirname, 'uploads/media');

[eventUploadDir, mediaUploadDir].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
     if (file.fieldname === 'eventImage') {
      cb(null, eventUploadDir);
    } else if (file.fieldname === 'mediaImage') {
      cb(null, mediaUploadDir);
    } else {
      cb(null, 'uploads/');
    }
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });
// ================================
// Middleware Functions
// ================================

/**
 * verifyToken middleware: Checks for a valid JWT in the Authorization header.
 */
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1]; // Expected format: "Bearer <token>"
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Session expired Please login ' });
    }
    req.user = decoded;
    next();
  });
}

/**
 * verifyAdmin middleware: Checks if the user has an admin role.
 */
function verifyAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') {
    return next();
  } 
  return res.status(403).json({ error: 'Access denied: Admins only' });
}   


/**
 * POST /parents/login
 * Authenticates a parent and returns a JWT token.
 */
app.post('/parents/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await db.promise().query(
      'SELECT * FROM parents WHERE email = ?',
      [email]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }
    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }
    // Generate JWT token (expires in 1 hour)
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );
    res.json({ token });
  } catch (err) {
    console.error('Login Error:', err);
    res.status(500).json({ error: 'Server error during login.' });
  }
});


// ================================
// Events Endpoints
// ================================
app.get('/events', async (req, res) => {
  try {
    const [rows] = await db.promise().query('SELECT * FROM events ORDER BY id DESC');

    // Format each event's date
    rows.forEach(event => {
      if (event.event_date) {
        const date = new Date(event.event_date);
        const day = String(date.getDate()).padStart(2, '0');
        const month = date.toLocaleString('en-US', { month: 'short' }).toUpperCase();
        const year = date.getFullYear();
        event.event_date = `${day} ${month} ${year}`;  // Format: 03 MAY 2025
      }
    });

    res.json(rows);
  } catch (error) {
    console.error('Error fetching events:', error);
    res.status(500).json({ error: error.message });
  }
});



app.post('/admin/events', upload.single('eventImage'), async (req, res) => {
  try {
    console.log("Received body:", req.body);  // Debug: Check text fields
    console.log("Received file:", req.file);    // Debug: Check file info

    const { title, description, event_date } = req.body;
    if (!title || !title.trim()) {
      return res.status(400).json({ error: 'Title is required.' });
    }

    let image_url = null;
    if (req.file) {
      // Construct the relative URL directly:
      image_url = 'uploads/events/' + req.file.filename;
    }
    const [result] = await db.promise().query(
      'INSERT INTO events (title, description, event_date, image_url) VALUES (?, ?, ?, ?)',
      [title, description, event_date, image_url]
    );

    res.status(201).json({ message: 'Event added successfully.', eventId: result.insertId });
  } catch (error) {
    console.error('Error adding event:', error);
    // Return the actual error message so you can see what went wrong.
    res.status(500).json({ error: error.message });
  }
});
/**
 * PUT /admin/events/:id
 * Updates an event (Admin Only).
 */
app.put('/admin/events/:id', verifyToken, verifyAdmin, upload.single('eventImage'), async (req, res) => {
  try {
    const eventId = req.params.id;
    const { title, description, event_date } = req.body;
    const image_url = req.file ? req.file.path : null;
    let query, params;
    if (image_url) {
      query = 'UPDATE events SET title = ?, description = ?, event_date = ?, image_url = ? WHERE id = ?';
      params = [title, description, event_date, image_url, eventId];
    } else {
      query = 'UPDATE events SET title = ?, description = ?, event_date = ? WHERE id = ?';
      params = [title, description, event_date, eventId];
    }
    const [result] = await db.promise().query(query, params);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Event not found.' });
    res.json({ message: 'Event updated successfully.' });
  } catch (error) {
    console.error('Error updating event:', error);
    res.status(500).json({ error: error.message });
  }
});



app.delete('/admin/events/:id', verifyToken, verifyAdmin, (req, res) => {
  const eventId = req.params.id;
  const sql = 'DELETE FROM events WHERE id = ?';
  db.query(sql, [eventId], (err, result) => {
    if (err) {
      console.error('Error deleting event:', err);
      return res.status(500).json({ error: 'Error deleting event' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.json({ message: 'Event deleted successfully' });
  });
});

  app.get('/admin/events',verifyToken, verifyAdmin, async (req, res) => {
  try {
    const [rows] = await db.promise().query('SELECT * FROM events');
    res.json(rows);
  } catch (error) {
    console.error('Error fetching events:', error);
    res.status(500).json({ error: error.message });
  }
});
// ================================
// Media Endpoints
// ================================

app.post('/admin/media', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: "Message is required." });
    const [result] = await db.promise().query(
      'INSERT INTO media (message) VALUES (?)',
      [message]
    );
    res.status(201).json({ message: "Media message added successfully.", mediaId: result.insertId });
  } catch (error) {
    console.error("Error adding media message:", error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/admin/media/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const mediaId = req.params.id;
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: "Message is required." });
    const [result] = await db.promise().query(
      'UPDATE media SET message = ? WHERE id = ?',
      [message, mediaId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Media record not found." });
    }
    res.json({ message: "Media message updated successfully." });
  } catch (error) {
    console.error("Error updating media message:", error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/admin/media/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const mediaId = req.params.id;
    const [result] = await db.promise().query(
      'DELETE FROM media WHERE id = ?',
      [mediaId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Media record not found." });
    }
    res.json({ message: "Media message deleted successfully." });
  } catch (error) {
    console.error("Error deleting media message:", error);
    res.status(500).json({ error: error.message });
  }
});


app.get('/admin/media', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const [rows] = await db.promise().query('SELECT * FROM media ORDER BY created_at DESC');
    res.json(rows);
  } catch (error) {
    console.error("Error fetching media messages (admin):", error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/media', async (req, res) => {
  try {
    const [rows] = await db.promise().query('SELECT * FROM media ORDER BY created_at DESC LIMIT 1');
    if (rows.length === 0) {
      return res.json({ message: "No media messages available." });
    }

    let media = rows[0];

    if (media.created_at) {
      const date = new Date(media.created_at);

      const day = String(date.getDate()).padStart(2, '0');
      const month = date.toLocaleString('en-US', { month: 'short' }).toUpperCase();
      const year = date.getFullYear();
      const hours = String (date.getHours()).padStart(2, '0');
      const minutes = String (date.getMinutes()).padStart(2, '0');

      media.created_at = `${day} ${month} ${year} ${hours}:${minutes}`;
    }

    res.json(media);
  } catch (error) {
    console.error("Error fetching media message (parent):", error);
    res.status(500).json({ error: error.message });
  }
});

// ================================
// Contact  Us endpoints 
// ================================
app.post("/contact-us", (req, res) => {
  const { first_name, second_name, email, contact_number, message } = req.body;

  const sql = "INSERT INTO contact_us (first_name, second_name, email, contact_number, message) VALUES (?, ?, ?, ?, ?)";
  const values = [first_name, second_name, email, contact_number, message];

  db.query(sql, values, (err, result) => {
      if (err) {
          console.error(err);
          return res.status(500).json({ error: "Database error" });
      }
      res.json({ success: true, message: "Message sent successfully!" });
  });
});

app.get("/admin/contact-messages", (req, res) => {
  const sql = "SELECT id, first_name, second_name, email, contact_number, message, created_at FROM contact_us ORDER BY created_at DESC";
  db.query(sql, (err, results) => {
      if (err) {
          console.error(err);
          return res.status(500).json({ error: "Database error" });
      }
      res.json(results);
  });
  });  
   app.delete("/admin/contact-messages-delete", (req, res) => {
  const sql = "DELETE FROM contact_us";
  db.query(sql, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Failed to delete messages" });
    }
    res.json({ 
      message: `Successfully deleted ${results.affectedRows} messages` 
    });
  });
});

  // ================================
// subscribers endpoints 
// ================================
app.post("/subscribe", (req, res) => {

  
  const { name, email } = req.body;

  if (!name || !email) {
    return res.status(400).json({ error: "Name and email are required." });
  }

  const sql = "INSERT INTO subscribers (name, email) VALUES (?, ?)";

  db.query(sql, [name, email], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: "Email already subscribed." });
      }
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error." });
    }

    // ✅ Set up email with embedded logo
    const mailOptions = {
      from: `"Daycare Team" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'THANK YOU  FOR  SUBSCRIBING !',
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;"> 
        
          <h2 style="color:red;">Welcome to Lerato Daycare  ${name}! </h2>
          <img src="cid:daycarelogo" alt="Daycare Logo" style="width: 170px; border-radius: 8px; margin-bottom: 20px;" />
          <p>One of the best child care centre in Modimolle. <br> 
          We are so excited to embark on this journey of learning and growth together. <br>
          We are committed to providing a nurturing, stimulating and safe environment, where every<br> 
          child feels valued, respected and encouraged to reach their full potential. <br> 
          We view parents as integral partners in this journey, we therefore encourage open <br>
          communication, collaboration and active involvement in our creche community wise <br> Again  we  
          thank you for subscribing! You’ll now get the latest news, events, and updates from us.</p>
          <p style="color: red; margin-top: 10px;">— The Daycare Team</p>
        </div>
      `,
      attachments: [
        {
          filename: 'logoB.png',
          path: path.join(__dirname, 'assert/logoB.png'),
          cid: 'daycarelogo' 
        }
      ]
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Email send error:", error);

      
        db.query('DELETE FROM subscribers WHERE email = ?', [email]);

        return res.status(500).json({ error: "Failed to send confirmation email." });
      }

      console.log('✅ Welcome email sent:', info.response);
      res.status(201).json({ message: "Successfully subscribed!" });
    });
  });
});

app.get("/admin/subscribers/count", verifyToken, verifyAdmin, (req, res) => {
  db.query('SELECT COUNT(*) AS total FROM subscribers', (err, results) => {
    if (err) {
      console.error("Error fetching subscriber count:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ total: results[0].total });
  });
});
 app.get("/admin/events/count", verifyToken, verifyAdmin, (req, res) => {
  db.query('SELECT COUNT(*) AS total FROM events', (err, results) => {
    if (err) {
      console.error("Error fetching events count:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ total: results[0].total });
  });
}); 
app.get("/admin/messages/count", verifyToken, verifyAdmin, (req, res) => {
  db.query('SELECT COUNT(*) AS total FROM contact_us ', (err, results) => {
    if (err) {
      console.error("Error fetching messages count:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ total: results[0].total });
  });
});


app.get("/admin/subscribers", verifyToken, verifyAdmin, (req, res) => {
  db.query('SELECT id, name, email FROM subscribers ORDER BY id DESC', (err, results) => {
    if (err) {
      console.error("Error fetching subscribers:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(results);
  });
});
 
app.delete("/admin/subscribers/:id", verifyToken, verifyAdmin, (req, res) => { 
  console.log("Received ID:", req.params.id);
  const subscriberId = parseInt(req.params.id, 10);

  if (isNaN(subscriberId)) {
    return res.status(400).json({ error: "Invalid subscriber ID" });
  }

  db.query('DELETE FROM subscribers WHERE id = ?', [subscriberId], (err, result) => {
    if (err) {
      console.error("Error deleting subscriber:", err);
      return res.status(500).json({ error: "Database error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Subscriber not found" });
    }

    res.json({ message: "Subscriber deleted successfully" });
  });
});
// Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
