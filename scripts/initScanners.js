const mongoose = require('mongoose');
const config = require('../config.js');
const ScannerAssignment = require('../models/ScannerAssignment.js');

async function initScanners() {
    try {
        console.log('🔌 Connecting to MongoDB...');
        await mongoose.connect(config.MONGODB_URI);
        console.log('✅ Connected to MongoDB');

        // Tạo dữ liệu mẫu cho 2 máy quét
        const sampleScanners = [
            {
                scannerId: 'SCANNER_001',
                scannerName: 'Máy quét bàn 1',
                status: 'available'
            },
            {
                scannerId: 'SCANNER_002', 
                scannerName: 'Máy quét bàn 2',
                status: 'available'
            }
        ];

        console.log('📝 Creating sample scanners...');
        
        for (const scannerData of sampleScanners) {
            const existing = await ScannerAssignment.findOne({ scannerId: scannerData.scannerId });
            
            if (existing) {
                console.log(`⚠️  Scanner ${scannerData.scannerId} already exists`);
            } else {
                const scanner = new ScannerAssignment(scannerData);
                await scanner.save();
                console.log(`✅ Created scanner: ${scannerData.scannerId} - ${scannerData.scannerName}`);
            }
        }

        // Hiển thị tất cả scanners
        const allScanners = await ScannerAssignment.find({});
        console.log('\n📋 All scanners:');
        allScanners.forEach(scanner => {
            console.log(`  - ${scanner.scannerId}: ${scanner.scannerName} (${scanner.status})`);
        });

        console.log('\n🎉 Scanner initialization completed!');
        process.exit(0);

    } catch (error) {
        console.error('❌ Error:', error);
        process.exit(1);
    }
}

initScanners();
