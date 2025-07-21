const mongoose = require('mongoose');

const formSubmissionSchema = new mongoose.Schema({
  formId: {
    type: String,
    required: true,
    index: true
  },
  answers: [{
    fieldId: {
      type: String,
      required: true
    },
    fieldLabel: {
      type: String
    },
    value: {
      type: mongoose.Schema.Types.Mixed,
      default: ''
    }
  }],
  submittedAt: {
    type: Date,
    default: Date.now
  },
  templateInfo: {
    type: Object,
    required: false
  }
}, {
  timestamps: true
});

// Index for better query performance
formSubmissionSchema.index({ formId: 1, submittedAt: -1 });

module.exports = mongoose.model('FormSubmission', formSubmissionSchema); 