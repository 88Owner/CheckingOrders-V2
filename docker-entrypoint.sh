#!/bin/bash

# Docker entrypoint script for OrderCheck application


# Wait for MongoDB to be ready
node -e "
const mongoose = require('mongoose');
const config = require('./config');

async function waitForMongo() {
    let retries = 30;
    while (retries > 0) {
        try {
            await mongoose.connect(config.MONGODB_URI, {
                useNewUrlParser: true,
                useUnifiedTopology: true
            });
            console.log('✅ MongoDB connected successfully');
            await mongoose.disconnect();
            break;
        } catch (error) {
            console.log('⏳ MongoDB not ready, retrying in 2 seconds...');
            retries--;
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }
    if (retries === 0) {
        console.error('❌ Failed to connect to MongoDB after 60 seconds');
        process.exit(1);
    }
}

waitForMongo();
"

# Run migration if needed
node -e "
const mongoose = require('mongoose');
const config = require('./config');
const ScannerAssignment = require('./models/ScannerAssignment');
const Account = require('./models/Account');

async function runMigration() {
    try {
        await mongoose.connect(config.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        
        console.log('📋 Checking for existing assignments...');
        const existingAssignments = await ScannerAssignment.countDocuments();
        
        if (existingAssignments === 0) {
            console.log('🔄 No assignments found, running migration...');
            
            // Get accounts with scanner permissions
            const accounts = await Account.find({
                'scannerPermissions.port': { \$exists: true, \$ne: null }
            });
            
            console.log(\`📋 Found \${accounts.length} accounts with COM port assignments\`);
            
            // Migrate each account
            for (const account of accounts) {
                const port = account.scannerPermissions.port;
                if (port) {
                    const assignment = new ScannerAssignment({
                        userId: account.username,
                        comPort: port.toUpperCase()
                    });
                    await assignment.save();
                    console.log(\`✅ Migrated: \${account.username} -> \${port}\`);
                }
            }
            
            console.log('🎉 Migration completed successfully!');
        } else {
            console.log(\`✅ Found \${existingAssignments} existing assignments, skipping migration\`);
        }
        
        await mongoose.disconnect();
    } catch (error) {
        console.error('❌ Migration failed:', error.message);
        process.exit(1);
    }
}

runMigration();
"

# Start the application
echo "Starting OrderCheck server..."
exec node server.js
