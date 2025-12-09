const mongoose = require('mongoose');

const doiTuongCatVaiSchema = new mongoose.Schema({
    // ID để nhập lại cho lần cắt sau
    catVaiId: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    // Thông tin mẫu vải
    maMau: {
        type: String,
        required: true
    },
    tenMau: {
        type: String,
        required: true
    },
    // Ngày nhập
    ngayNhap: {
        type: Date,
        default: Date.now
    },
    // Nhân viên nào
    createdBy: {
        type: String,
        required: true
    },
    // Chiều dài cây vải ban đầu
    chieuDaiCayVai: {
        type: Number,
        required: true,
        min: 0
    },
    // Diện tích ban đầu
    dienTichBanDau: {
        type: Number,
        required: true,
        min: 0
    },
    // Diện tích đã cắt
    dienTichDaCat: {
        type: Number,
        default: 0,
        min: 0
    },
    // Diện tích còn lại
    dienTichConLai: {
        type: Number,
        default: 0,
        min: 0
    },
    // Số m còn lại
    soMConLai: {
        type: Number,
        default: 0,
        min: 0
    },
    // Tiến độ
    tienDoPercent: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    },
    // Vải lỗi
    vaiLoi: {
        chieuDai: { type: Number, default: 0 },
        dienTich: { type: Number, default: 0 },
        soM: { type: Number, default: 0 }
    },
    // Vải thiếu
    vaiThieu: {
        soM: { type: Number, default: 0 }
    },
    // Nhập lại kho
    nhapLaiKho: {
        soM: { type: Number, default: 0 }
    },
    // Danh sách kích thước đã cắt
    items: [{
        kichThuoc: String,
        szSku: String,
        soLuong: Number,
        dienTich: Number,
        dienTichCat: Number
    }],
    // Lịch sử các lần cắt (để theo dõi)
    lichSuCat: [{
        ngayCat: { type: Date, default: Date.now },
        items: [{
            kichThuoc: String,
            szSku: String,
            soLuong: Number,
            dienTich: Number,
            dienTichCat: Number
        }],
        dienTichDaCat: Number,
        dienTichConLai: Number,
        soMConLai: Number,
        vaiLoi: {
            chieuDai: { type: Number, default: 0 },
            dienTich: { type: Number, default: 0 },
            soM: { type: Number, default: 0 }
        },
        vaiThieu: {
            soM: { type: Number, default: 0 }
        },
        nhapLaiKho: {
            soM: { type: Number, default: 0 }
        },
        createdBy: String
    }],
    // Trạng thái: active, completed, archived
    trangThai: {
        type: String,
        enum: ['active', 'completed', 'archived'],
        default: 'active'
    }
}, {
    timestamps: true
});

// Index để tìm kiếm nhanh
doiTuongCatVaiSchema.index({ catVaiId: 1 });
doiTuongCatVaiSchema.index({ maMau: 1, ngayNhap: -1 });
doiTuongCatVaiSchema.index({ createdBy: 1, ngayNhap: -1 });
doiTuongCatVaiSchema.index({ trangThai: 1 });

module.exports = mongoose.model('DoiTuongCatVai', doiTuongCatVaiSchema);

