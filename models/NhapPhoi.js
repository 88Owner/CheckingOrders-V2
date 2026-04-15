const mongoose = require('mongoose');

const nhapPhoiSchema = new mongoose.Schema(
    {
        maMau: {
            type: String,
            required: true
        },
        tenMau: {
            type: String,
            required: true
        },
        kichThuoc: {
            type: String,
            required: true
        },
        szSku: {
            type: String,
            required: true
        },
        soLuong: {
            type: Number,
            required: true,
            min: 0
        },
        /** Số tấm lỗi (theo dòng nhập phôi) — dùng cho cột N/O khi xuất CSV */
        slLoi: {
            type: Number,
            default: 0,
            min: 0
        },
        /** Số m vải lỗi (snapshot theo lần nhập / đối tượng cắt) */
        soMLoi: {
            type: Number,
            required: false
        },
        /** SKU hàng lỗi: mã mẫu + hậu tố (mặc định 00-404-230) */
        skuHangLoi: {
            type: String,
            default: null,
            trim: true
        },
        createdBy: {
            type: String,
            required: true
        },
        importDate: {
            type: Date,
            default: Date.now
        },
        /** Đối tượng cắt vải (1 cây vải) — mỗi lần nhập là bản ghi riêng */
        catVaiId: {
            type: String,
            default: null,
            trim: true
        }
    },
    {
        timestamps: true
    }
);

nhapPhoiSchema.index({ maMau: 1, kichThuoc: 1 });
nhapPhoiSchema.index({ createdBy: 1, importDate: -1 });
nhapPhoiSchema.index({ catVaiId: 1, createdAt: -1 });

module.exports = mongoose.model('NhapPhoi', nhapPhoiSchema);
