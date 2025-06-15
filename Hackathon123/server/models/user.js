import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import validator from 'validator';

const userSchema = new mongoose.Schema({
  // Personal Information
  firstName: {
    type: String,
    required: true,
    trim: true
  },
  lastName: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  phoneNumber: {
    type: String,
    required: [true, 'Phone number is required'],
    unique: true,
    validate: {
      validator: function(v) {
        return /^\+?[0-9]{10,15}$/.test(v); // Basic phone number validation
      },
      message: 'Please provide a valid phone number'
    }
  },
  // Address Details
  physicalAddress: {
    type: String,
    required: [true, 'Physical address is required'],
    trim: true
  },
  postalAddress: {
    type: String,
    required: [true, 'Postal address is required'],
    trim: true
  },
  // Additional Personal Details
  gender: {
    type: String,
    enum: ['male', 'female', 'other', 'prefer-not-to-say'],
    required: false
  },
  id: {
    type: String, // Could be passport, driver's license, etc.
    required: [true, 'ID is required for KYC'],
    unique: true
  },
  dob: {
    type: Date,
    required: [true, 'Date of birth is required'],
    validate: {
      validator: function(v) {
        return v < new Date(); // Ensure DOB is in the past
      },
      message: 'Date of birth must be valid'
    }
  },
  occupation: {
    type: String,
    required: [true, 'Occupation is required'],
    trim: true
  },
  // Security & Authentication
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  confirmPassword: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      validator: function(el) {
        return el === this.password;
      },
      message: 'Passwords do not match'
    }
  },
  // Timestamps & Status
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    this.confirmPassword = undefined; // Remove confirmPassword after validation
    next();
  } catch (error) {
    next(error);
  }
});

// Update 'updatedAt' on document updates
userSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Method to return user data without sensitive info
userSchema.methods.toJSON = function() {
  const user = this;
  const userObject = user.toObject();
  
  // Remove sensitive fields
  delete userObject.password;
  delete userObject.confirmPassword;
  delete userObject.__v;
  
  return userObject;
};

// Check if model exists before creating
const User = mongoose.models.User || mongoose.model('User', userSchema);

export default User;