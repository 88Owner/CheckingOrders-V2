const mongoose = require('mongoose');

const databaseConfigSchema = new mongoose.Schema({
    currentDbType: {
        type: String,
        enum: ['local', 'cloud'],
        default: 'local',
        required: true
    },
    lastBackupTime: {
        type: Date,
        default: null
    },
    localDbUri: {
        type: String,
        default: 'mongodb://localhost:27017/OrderDetailing'
    },
    cloudDbUri: {
        type: String,
        default: 'mongodb+srv://shisonson_db:05092003@cluster0.0vbnezg.mongodb.net/?appName=Cluster0'
    }
}, {
    timestamps: true
});

// Ensure only one document exists
databaseConfigSchema.statics.getConfig = async function() {
    let config = await this.findOne();
    if (!config) {
        config = await this.create({
            currentDbType: 'local',
            localDbUri: 'mongodb://localhost:27017/OrderDetailing',
            cloudDbUri: 'mongodb+srv://shisonson_db:05092003@cluster0.0vbnezg.mongodb.net/?appName=Cluster0'
        });
    }
    return config;
};

module.exports = mongoose.model('DatabaseConfig', databaseConfigSchema);

