const mongoose = require('mongoose');
const config = require('../config');
const Account = require('../models/Account');
(async () => {
  try {
    await mongoose.connect(config.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    const accounts = await Account.find().lean();
    console.log('Accounts:', accounts);
    process.exit(0);
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
})();