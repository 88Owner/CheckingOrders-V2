const mongoose = require('mongoose');
const config = require('../config.js');
const ScannerAssignment = require('../models/ScannerAssignment.js');

async function checkScanners() {
    try {
        await mongoose.connect(config.MONGODB_URI);
        console.log('✅ Connected to MongoDB');
        
        const scanners = await ScannerAssignment.find({});
        console.log('\n📋 Current scanners in database:');
        
        if (scanners.length === 0) {
            console.log('❌ No scanners found in database');
        } else {
            scanners.forEach((scanner, index) => {
                console.log(`${index + 1}. ID: ${scanner.scannerId}`);
                console.log(`   Name: ${scanner.scannerName}`);
                console.log(`   Status: ${scanner.status}`);
                console.log(`   Assigned to: ${scanner.assignedTo || 'None'}`);
                console.log(`   Session: ${scanner.sessionId || 'None'}`);
                console.log(`   Created: ${scanner.createdAt}`);
                console.log('---');
            });
        }
        
        process.exit(0);
    } catch (error) {
        console.error('❌ Error:', error);
        process.exit(1);
    }
}

checkScanners();
