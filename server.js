// working perfect
const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");
const cors = require("cors");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
// const authRoutes = require("./routes/auth");
const cloudinary = require("cloudinary").v2; // Import Cloudinary
require("dotenv").config();
const nodemailer = require("nodemailer");
const path = require("path");
const fs = require("fs");
const app = express();
const PORT = process.env.PORT || 5000;
const session = require("express-session");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const OAuth2Strategy = require("passport-google-oauth2").Strategy;
const User = require("./models/User");
const crypto = require("crypto"); // To generate a random OTP
const FormSubmission = require("./models/FormSubmission");
// Middleware
const jwtSecret = process.env.JWT_SECRET;

app.use(bodyParser.json());
app.use(cors({
  origin: [
    'http://localhost:3000',            // Local React dev server
    'http://localhost:5173',            // Local Vite dev server
    'https://createanytypeform.netlify.app'  // Live frontend
  ],
  credentials: true,                    // Allow cookies, sessions, etc.
  methods: "GET,POST,PUT,DELETE"        // Allowed HTTP methods
}));

app.use(express.json());
// Configure Cloudinary
cloudinary.config({
  cloud_name: "dfbtey2ld",
  api_key: "523974768834469",
  api_secret: "E0zGVyzWVacljB3cn8VNloyRNQk",
});

// Test Cloudinary connection
cloudinary.api.ping()
  .then(result => {
    console.log("Cloudinary connection successful:", result);
  })
  .catch(error => {
    console.error("Cloudinary connection failed:", error);
  });

let users = {
  "audreanne.wunsch48@ethereal.email": { password: "EXW5anVZCbcHJbD76r" },
};
let otps = {};

const sendMail = async (email, otp) => {
  let transporter = nodemailer.createTransport({
    host: "smtp.ethereal.email",
    port: 587,
    auth: {
      user: "audreanne.wunsch48@ethereal.email", // replace with your ethereal email
      pass: "EXW5anVZCbcHJbD76r", // replace with your ethereal password
    },
  });

  await transporter.sendMail({
    from: "alid13381@gmail.com",
    to: email,
    subject: "Your OTP for Password Reset",
    text: `Your OTP is: ${otp}`,
    html: `<b>Your OTP is: ${otp}</b>`,
  });
};

app.post("/api/forgotpassword", async (req, res) => {
  const { email } = req.body;

  if (!users[email]) {
    return res.status(404).json({ message: "User not found" });
  }

  const otp = crypto.randomInt(100000, 999999).toString();
  otps[email] = otp;

  await sendMail(email, otp);
  res.status(200).json({ message: "OTP sent to your email" });
});

app.post("/api/resetpassword", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  // Check if OTP is valid
  if (otps[email] && otps[email] === otp) {
    try {
      // Find the user by email
      let user = await User.findOne({ email });

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Update the password field with the new password (it will be hashed in the pre-save hook)
      user.password = newPassword;

      // Save the updated user
      await user.save();

      // Delete the OTP as it's no longer needed
      delete otps[email];

      console.log(`Updated password for ${email}: ${user.password}`); // Debugging line
      return res.status(200).json({ message: "Password updated successfully" });
    } catch (err) {
      return res.status(500).json({ message: "Error updating password" });
    }
  } else {
    return res.status(400).json({ message: "Invalid OTP" });
  }
});

// Sample user for demo purposes

// Forgot Password Route

app.post("/api/resetpassword", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (otps[email] && otps[email] === otp) {
    // Hash the new password before saving it
    try {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);

      // Update the user's password in MongoDB
      users[email].password = hashedPassword;

      // Delete the OTP as it's no longer needed
      delete otps[email];

      console.log(`Updated password for ${email}: ${users[email].password}`); // Debugging line
      return res.status(200).json({ message: "Password updated successfully" });
    } catch (err) {
      return res.status(500).json({ message: "Error updating password" });
    }
  } else {
    return res.status(400).json({ message: "Invalid OTP" });
  }
});

app.use(
  session({
    secret: "acn546dnwjn", // Use a strong secret
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Set to true if using HTTPS
  })
);
app.use(passport.initialize());
app.use(passport.session());
const clientid =
  "751697629319-kgjmketp0t3dj8hoaqe7vi18ef6fs73a.apps.googleusercontent.com";
const clientsecret = "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";

passport.use(
  new OAuth2Strategy(
    {
      clientID: clientid,
      clientSecret: clientsecret,
      callbackURL: "/auth/google/callback",
      scope: ["profile", "email"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
          user = new User({
            googleId: profile.id,
            displayName: profile.displayName,
            email: profile.emails[0].value,
            image: profile.photos[0].value,
          });

          await user.save();
        }

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// initial google ouath login
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    successRedirect: "http://localhost:3000",
    failureRedirect: "http://localhost:3000/login",
  })
);

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: "Email already in use" });

    user = new User({ name, email, password });
    await user.save();

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, jwtSecret, { expiresIn: "1h" });

    // Store token in cookie (HTTP-only cookie)
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Use secure cookies in production
      sameSite: "strict", // Prevent CSRF
    });

    res.status(201).json({
      message: "Signup successful",
      token, // Optionally, send token back for frontend storage if needed
      user: { id: user._id, name: user.name, email: user.email }, // Send user data
    });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Login Route
// Login Route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });
    console.log(user);
    const isMatch = await user.comparePassword(password); // Assuming you have a password comparison method
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, jwtSecret, { expiresIn: "1h" });
    console.log(token);

    // Store token in cookie (HTTP-only cookie)
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Use secure cookies in production
      sameSite: "strict", // Prevent CSRF
    });
    console.log(res);
    // Send the user data to the frontend
    res.json({
      message: "Login successful",
      token, // Send token
      user: { id: user._id, name: user.name, email: user.email }, // Send user data
    });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// app.get('/login/success', (req, res) => {
//   console.log(req.user); // Check the user data
//   if (req.isAuthenticated()) {
//     res.status(200).json({
//       user: req.user,
//       message: 'Login successful',
//     });
//   } else {
//     res.status(401).json({ message: 'Not authenticated' });
//   }
// });

app.get("/login/success", (req, res) => {
  console.log(req.cookies); // Log cookies to debug
  console.log(req.user); // Check the user data
  if (req.isAuthenticated()) {
    res.status(200).json({
      user: req.user,
      message: "Login successful",
    });
  } else {
    res.status(401).json({ message: "Not authenticated" });
  }
});

app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    req.session.destroy((err) => {
      if (err) {
        return next(err);
      }
      // Instead of redirecting, send a success message
      res.status(200).json({ message: "Logged out successfully" });
    });
  });
});

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, "uploads");
const pdfsDir = path.join(__dirname, "uploads/pdfs");

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
if (!fs.existsSync(pdfsDir)) {
  fs.mkdirSync(pdfsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, pdfsDir); // Save all files here
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`); // Save with a unique name
  },
});

// File filter to allow multiple file types
const fileFilter = (req, file, cb) => {
  // Allow images, PDFs, documents, and other common file types
  const allowedTypes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/plain',
    'application/zip',
    'application/x-zip-compressed'
  ];
  
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`File type ${file.mimetype} not allowed`), false);
  }
};

const upload = multer({ 
  storage,
  fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Connect to MongoDB

mongoose
  .connect("mongodb+srv://alid13381:danish29@cluster0.ucjqbgd.mongodb.net/", {
    // useNewUrlParser: true,
    // useUnifiedTopology: true, // You can remove this
  })
  .then(() => {
    console.log("MongoDB connected");
  })
  .catch((error) => {
    console.error("MongoDB connection error:", error);
  });

// Define the form schema
const formSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  info: { type: String, required: false },
  fields: { type: Array, required: true },
  imageUrl: { type: String, required: false }, // Add imageUrl field
  path: { type: String, required: false }, // Add path field (assuming you want to include it)
  layout: { type: Array, required: false },
  templateId: { type: Number, required: false, default: 1 },
  createdByIp: { type: String, required: false }, // Track guest form creation by IP
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false }, // Track logged-in user
  isPublic: { type: Boolean, default: false }, // Public/private toggle
  expirationDateTime: { type: Date, required: false }, // Expiration date/time
});

const Form = mongoose.model("Form", formSchema);

app.post("/api/forms", upload.single("file"), async (req, res) => {
  try {
    // 1. Check if user is logged in (adjust as per your auth system)
    const user = req.user || (req.body.userId ? await User.findById(req.body.userId) : null); // fallback for token auth

    // 2. If not logged in, count forms by IP
    if (!user) {
      const ip = req.ip;
      const formCount = await Form.countDocuments({ createdByIp: ip });
      if (formCount >= 3) {
        return res.status(403).json({
          message: "You can create up to 3 forms for free. Please log in to create more."
        });
      }
    }

    const formData = req.body;
    let fileUrl = null;

    // Upload file to Cloudinary if provided
    if (req.file) {
      try {
        const uploadOptions = {
          resource_type: "auto", // Automatically determines the type (image, video, etc.)
        };
        const result = await cloudinary.uploader.upload(req.file.path, uploadOptions);
        fileUrl = result.secure_url;
      } catch (uploadError) {
        console.error("Cloudinary upload error:", uploadError);
      }
    }

    const newForm = new Form({
      id: formData.id || uuidv4(),
      name: formData.name,
      info: formData.info,
      fields: formData.fields,
      imageUrl: fileUrl || "",
      path: formData.path || "",
      layout: formData.layout || [],
      templateId: formData.templateId ? Number(formData.templateId) : 1,
      createdByIp: user ? undefined : req.ip,
      userId: user ? user._id : undefined,
    });

    await newForm.save();
    return res
      .status(201)
      .json({ message: "Form saved successfully!", newForm });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/forms", async (req, res) => {
  try {
    let forms;
    // Check if user is logged in (adjust as per your auth system)
    const user = req.user || (req.query.userId ? await User.findById(req.query.userId) : null);
    if (user) {
      // Return only forms created by this user
      forms = await Form.find({ userId: user._id });
    } else {
      // Return only forms created by this IP (for guests)
      forms = await Form.find({ createdByIp: req.ip });
    }
    return res.status(200).json(forms);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Get a form by ID
app.get("/api/forms/:id", async (req, res) => {
  try {
    const form = await Form.findOne({ id: req.params.id });
    if (!form) {
      return res.status(404).json({ message: "Form not found" });
    }
    // Check if user is logged in (adjust as per your auth system)
    const user = req.user || (req.query.userId ? await User.findById(req.query.userId) : null);
    if (user) {
      if (!form.userId || form.userId.toString() !== user._id.toString()) {
        return res.status(403).json({ message: "You do not have permission to view this form." });
      }
    } else {
      // Guest: check IP
      if (!form.createdByIp || form.createdByIp !== req.ip) {
        return res.status(403).json({ message: "You do not have permission to view this form." });
      }
    }
    return res.status(200).json(form);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Update a form by ID
app.put("/api/forms/:id", async (req, res) => {
  try {
    const { name, info, fields, layout, imageUrl, templateId, isPublic, expirationDateTime } = req.body;

    const updatedForm = await Form.findOneAndUpdate(
      { id: req.params.id },
      { name, info, fields, layout, imageUrl, templateId: templateId ? Number(templateId) : 1, isPublic, expirationDateTime },
      { new: true, runValidators: true }
    );

    if (!updatedForm) {
      return res.status(404).json({ message: "Form not found" });
    }

    return res
      .status(200)
      .json({ message: "Form updated successfully!", updatedForm });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Delete a form by ID
app.delete("/api/forms/:id", async (req, res) => {
  try {
    const deletedForm = await Form.findOneAndDelete({ id: req.params.id });

    if (!deletedForm) {
      return res.status(404).json({ message: "Form not found" });
    }

    return res.status(200).json({ message: "Form deleted successfully!" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Simple test upload endpoint
app.post("/api/forms/upload-test", upload.single("file"), async (req, res) => {
  console.log("Test upload endpoint hit");
  console.log("File received:", req.file);
  
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  try {
    console.log(`Uploading ${req.file.originalname} to Cloudinary...`);
    const result = await cloudinary.uploader.upload(req.file.path, {
      resource_type: "auto",
      folder: "form-builder-files",
    });
    
    console.log(`Successfully uploaded to Cloudinary: ${result.secure_url}`);
    
    // Clean up local file
    fs.unlinkSync(req.file.path);
    
    res.json({ 
      url: result.secure_url, 
      message: "File uploaded to Cloudinary successfully" 
    });
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({ error: "Upload failed", details: error.message });
  }
});

app.post("/api/forms/upload", upload.array("files", 10), async (req, res) => {
  console.log("Upload endpoint hit");
  console.log("Files received:", req.files);
  
  if (!req.files || req.files.length === 0) {
    console.log("No files in request");
    return res.status(400).json({ error: "No files uploaded" });
  }

  try {
    const uploadPromises = req.files.map(async (file) => {
      console.log(`Processing file: ${file.originalname}, path: ${file.path}`);
      
      try {
        // Check if file exists
        if (!fs.existsSync(file.path)) {
          console.error(`File does not exist: ${file.path}`);
          throw new Error(`File not found: ${file.path}`);
        }

        // Upload to Cloudinary
        const uploadOptions = {
          resource_type: "auto", // Automatically determines the type (image, video, etc.)
          folder: "form-builder-files", // Optional: organize files in a folder
        };

        console.log(`Uploading ${file.originalname} to Cloudinary...`);
        const result = await cloudinary.uploader.upload(file.path, uploadOptions);
        console.log(`Successfully uploaded to Cloudinary: ${result.secure_url}`);
        
        // Clean up the local file after successful upload
        try {
          fs.unlinkSync(file.path);
          console.log(`Deleted local file: ${file.path}`);
        } catch (deleteError) {
          console.error(`Error deleting local file: ${deleteError}`);
        }
        
        return result.secure_url;
      } catch (uploadError) {
        console.error(`Error uploading ${file.originalname} to Cloudinary:`, uploadError);
        // If Cloudinary upload fails, return local URL as fallback
        console.log(`Falling back to local storage for ${file.originalname}`);
        return `http://localhost:${PORT}/uploads/pdfs/${file.filename}`;
      }
    });

    const urls = await Promise.all(uploadPromises);
    console.log("All uploads completed. URLs:", urls);
    
    // Check if all files were uploaded to Cloudinary
    const cloudinaryUrls = urls.filter(url => url.includes('cloudinary'));
    const localUrls = urls.filter(url => url.includes('localhost'));
    
    let message = `${urls.length} file(s) uploaded successfully`;
    if (cloudinaryUrls.length > 0 && localUrls.length === 0) {
      message += ' to Cloudinary';
    } else if (cloudinaryUrls.length > 0 && localUrls.length > 0) {
      message += ` (${cloudinaryUrls.length} to Cloudinary, ${localUrls.length} stored locally)`;
    } else {
      message += ' (stored locally)';
    }
    
    console.log("Sending response:", { urls, message });
    res.json({ urls, message });
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({ error: "Upload failed", details: error.message });
  }
});

// Test endpoint to verify server is working
app.get("/api/test", (req, res) => {
  res.json({ message: "Server is working", timestamp: new Date().toISOString() });
});

// Serve the uploaded files (optional)
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Form submission endpoint
app.post("/api/submit-form/:formId", async (req, res) => {
  try {
    const { formId } = req.params;
    const { answers, submittedAt, templateInfo } = req.body;

    // Create a new form submission
    const submission = new FormSubmission({
      formId,
      answers,
      submittedAt: submittedAt || new Date(),
      templateInfo: templateInfo || null
    });

    await submission.save();

    res.status(200).json({
      success: true,
      message: "Form submitted successfully",
      submissionId: submission._id
    });
  } catch (error) {
    console.error("Error submitting form:", error);
    res.status(500).json({
      success: false,
      message: "Error submitting form"
    });
  }
});

// Get form responses
app.get("/api/forms/:formId/responses", async (req, res) => {
  try {
    const { formId } = req.params;
    const form = await Form.findOne({ id: formId });
    if (!form) {
      return res.status(404).json({ message: "Form not found" });
    }
    // Allow public access if form is public
    if (!form.isPublic) {
      // Check if user is logged in (adjust as per your auth system)
      const user = req.user || (req.query.userId ? await User.findById(req.query.userId) : null);
      if (user) {
        if (!form.userId || form.userId.toString() !== user._id.toString()) {
          return res.status(403).json({ message: "You do not have permission to view these responses." });
        }
      } else {
        // Guest: check IP
        if (!form.createdByIp || form.createdByIp !== req.ip) {
          return res.status(403).json({ message: "You do not have permission to view these responses." });
        }
      }
    }
    const responses = await FormSubmission.find({ formId }).sort({ submittedAt: -1 });
    res.status(200).json(responses);
  } catch (error) {
    console.error("Error fetching responses:", error);
    res.status(500).json({ message: "Error fetching responses" });
  }
});

// Delete a specific response
app.delete("/api/responses/:responseId", async (req, res) => {
  try {
    const { responseId } = req.params;
    const deletedResponse = await FormSubmission.findByIdAndDelete(responseId);
    
    if (!deletedResponse) {
      return res.status(404).json({ message: "Response not found" });
    }

    res.status(200).json({ message: "Response deleted successfully" });
  } catch (error) {
    console.error("Error deleting response:", error);
    res.status(500).json({ message: "Error deleting response" });
  }
});

// Other routes remain unchanged...

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Single file upload to Cloudinary for form fileUpload fields
app.post("/api/upload", upload.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }
  try {
    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(req.file.path, {
      resource_type: "auto",
      folder: "form-builder-files",
    });
    // Clean up local file
    fs.unlinkSync(req.file.path);
    res.json({ url: result.secure_url });
  } catch (error) {
    console.error("Cloudinary upload error:", error);
    res.status(500).json({ error: "Upload failed", details: error.message });
  }
});

app.get("/api/forms/public/:id", async (req, res) => {
  try {
    const form = await Form.findOne({ id: req.params.id });
    if (!form) {
      return res.status(404).json({ message: "Form not found" });
    }
    if (!form.isPublic) {
      return res.status(403).json({ message: "This form is not public." });
    }
    if (form.expirationDateTime && new Date() > new Date(form.expirationDateTime)) {
      return res.status(403).json({ message: "This form has expired. Please contact the admin to reopen the form." });
    }
    return res.status(200).json(form);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});
